import os
from typing import Any
from uuid import uuid4

from fastapi import FastAPI
from pydantic import Field

from backend.apps.gateway.runtime import create_runtime
from backend.services.persistence import PersistenceCoordinator
from backend.shared.contracts import ActionRequest, Decision, DecisionOutcome, HealthResponse, Reason, ReasonCode, StrictModel


class GatewayActionRequest(ActionRequest):
    token: str = Field(min_length=1)
    llm_metadata: dict[str, str] | None = None


class ExecutionResponse(StrictModel):
    decision: Decision
    result: dict[str, Any] | None = None


class AuditVerificationResponse(StrictModel):
    verified: bool
    checked_events: int
    error: str | None = None


class TokenIssueRequest(StrictModel):
    agent_id: str
    task_id: str = "task-1"
    capability_version: str = "cap-v1"
    scope: list[str] | None = None
    security_epoch: int = 0
    lifetime_seconds: int = 300


app = FastAPI(
    title="AgentGuard Gateway",
    version="0.1.0",
    description="Phase 1 deterministic security Gateway.",
)

from backend.services.replay import ReplayAction, ReplayEngine
from backend.services.trace_graph import TraceGraphService

gateway, identity_service, executor = create_runtime()
persistence = PersistenceCoordinator() if os.getenv("AGENTGUARD_PERSISTENCE", "false").lower() == "true" else None
trace_graph = TraceGraphService()


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    return HealthResponse(status="ok", mode=os.getenv("LLM_MODE", "replay"))


@app.post("/tokens/issue", tags=["identity"])
async def issue_token(req: TokenIssueRequest) -> dict[str, Any]:
    agent = gateway.agents.get(req.agent_id)
    if req.scope is not None:
        scopes = frozenset(req.scope)
    else:
        scopes = agent.scopes if agent else frozenset()
    token = identity_service.issue_token(
        agent_id=req.agent_id,
        task_id=req.task_id,
        capability_version=req.capability_version,
        scope=scopes,
        security_epoch=req.security_epoch,
        lifetime_seconds=req.lifetime_seconds,
    )
    return {"token": token, "agent_id": req.agent_id, "task_id": req.task_id}



@app.post("/actions/evaluate", response_model=Decision, tags=["actions"])
async def evaluate_action(request: GatewayActionRequest, track_request: bool = False) -> Decision:
    decision = gateway.authorize(
        request.agent_id,
        request.tool_name,
        request.arguments,
        request.task_id,
        request.trace_id,
        request.token,
        request.execution_id,
        request.request_id if track_request else None,
    )
    risk_score = 75.0 if decision.decision == DecisionOutcome.BLOCK else (30.0 if decision.decision == DecisionOutcome.WARN else 10.0)
    trace_graph.record_step(
        request.trace_id,
        request.agent_id,
        request.task_id,
        request.tool_name,
        request.arguments,
        decision,
        request.execution_id,
        risk_score=risk_score,
        llm_metadata=request.llm_metadata,
    )
    if persistence is not None:
        persisted = await persistence.persist_authorization(request, decision)
        if persisted.conflict or (persisted.replayed and persisted.execution.lifecycle_state != "AUTHORIZED"):
            return Decision(
                decision=DecisionOutcome.BLOCK,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                task_id=request.task_id,
                trace_id=request.trace_id,
                execution_id=request.execution_id,
                reasons=(Reason(code=ReasonCode.REQUEST_REPLAYED if persisted.replayed else ReasonCode.EXECUTION_DUPLICATE, message="Request identity has already been processed." if persisted.replayed else "Idempotency key conflicts with an existing execution.", severity="critical", source="persistence"),),
            )
    return decision


@app.post("/actions/execute", response_model=ExecutionResponse, tags=["actions"])
async def execute_action(request: GatewayActionRequest) -> ExecutionResponse:
    decision = await evaluate_action(request, track_request=True)
    if decision.decision.value not in {"ALLOW", "WARN", "REQUIRE_APPROVAL"}:
        return ExecutionResponse(decision=decision)

    if decision.decision == DecisionOutcome.REQUIRE_APPROVAL and not request.approval_id:
        return ExecutionResponse(decision=decision)

    if persistence is not None:
        persisted = await persistence.persist_authorization(request, decision)
        if persisted.conflict or (persisted.duplicate and persisted.execution.lifecycle_state in {"SUCCEEDED", "EXECUTING", "UNKNOWN_RESULT"}):
            return ExecutionResponse(
                decision=Decision(
                    decision=DecisionOutcome.BLOCK,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    task_id=request.task_id,
                    trace_id=request.trace_id,
                    execution_id=request.execution_id,
                    reasons=(Reason(code=ReasonCode.EXECUTION_DUPLICATE, message="Execution already exists.", severity="critical", source="persistence"),),
                )
            )
        claimed, claim_succeeded = await persistence.claim_execution(request, decision)
        if not claim_succeeded or claimed.lifecycle_state != "EXECUTING":
            return ExecutionResponse(
                decision=Decision(
                    decision=DecisionOutcome.BLOCK,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    task_id=request.task_id,
                    trace_id=request.trace_id,
                    execution_id=request.execution_id,
                    reasons=(Reason(code=ReasonCode.EXECUTION_DUPLICATE, message="Execution is already claimed.", severity="critical", source="persistence"),),
                )
            )
    try:
        decision, result = gateway.execute_authorized(
            decision, request.agent_id, request.tool_name, request.arguments, approval_id=request.approval_id
        )
    except Exception:
        if persistence is not None:
            await persistence.persist_result(request, decision, "FAILED")
        raise

    if decision.reasons and any(r.code == ReasonCode.RESULT_UNKNOWN for r in decision.reasons):
        if persistence is not None:
            await persistence.persist_result(request, decision, "UNKNOWN_RESULT")
        return ExecutionResponse(decision=decision, result=None)

    if decision.decision == DecisionOutcome.BLOCK:
        if persistence is not None:
            await persistence.persist_result(request, decision, "FAILED")
        return ExecutionResponse(decision=decision, result=None)

    if persistence is not None:
        await persistence.persist_result(request, decision, "SUCCEEDED", result)
    return ExecutionResponse(decision=decision, result=result)


@app.post("/approvals/{approval_id}/approve", tags=["approvals"])
async def approve_action(approval_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    approval = gateway.approvals.approve(approval_id, payload)
    return {"approval_id": approval.approval_id, "status": approval.status.value, "fingerprint": approval.fingerprint}


@app.post("/approvals/{approval_id}/reject", tags=["approvals"])
async def reject_action(approval_id: str) -> dict[str, Any]:
    approval = gateway.approvals.reject(approval_id)
    return {"approval_id": approval.approval_id, "status": approval.status.value}


@app.get("/approvals", tags=["approvals"])
async def list_approvals() -> list[dict[str, Any]]:
    return [
        {"approval_id": a.approval_id, "status": a.status.value, "expires_at": a.expires_at, "fields": a.fields}
        for a in gateway.approvals.list()
    ]


@app.get("/incidents", tags=["incidents"])
async def list_incidents() -> list[dict[str, Any]]:
    return [
        {
            "incident_id": inc.incident_id,
            "agent_id": inc.agent_id,
            "task_id": inc.task_id,
            "trace_id": inc.trace_id,
            "reason_code": inc.reason_code,
            "severity": inc.severity,
            "state": inc.state.value,
            "created_at": inc.created_at,
        }
        for inc in gateway.incidents.list()
    ]


@app.get("/audit/verify", response_model=AuditVerificationResponse, tags=["audit"])
async def verify_audit() -> AuditVerificationResponse:
    if persistence is None:
        return AuditVerificationResponse(verified=False, checked_events=0, error="Persistence is disabled.")
    verification = await persistence.verify_audit()
    return AuditVerificationResponse(
        verified=verification.verified,
        checked_events=verification.checked_events,
        error=verification.error,
    )


@app.get("/agents", tags=["agents"])
async def list_agents() -> list[dict[str, Any]]:
    return [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "status": a.status.value,
            "security_state": a.security_state.value,
            "capability_version": a.capability_version,
            "task_id": a.task_id,
            "security_epoch": a.security_epoch,
            "allowed_tools": sorted(a.allowed_tools),
            "scopes": sorted(a.scopes),
        }
        for a in gateway.agents.list()
    ]


@app.get("/tools", tags=["tools"])
async def list_tools() -> list[dict[str, Any]]:
    return [
        {
            "tool_name": t.tool_name,
            "version": t.version,
            "description": t.description,
            "required_capability": t.required_capability,
            "enabled": t.enabled,
        }
        for t in gateway.tools.list()
    ]


@app.get("/graph", tags=["graph"])
async def get_graph() -> dict[str, Any]:
    from backend.services.trace_graph import TraceGraphService
    tg = TraceGraphService()
    # Populate with current registered agents and communication edges
    for a in gateway.agents.list():
        tg.graph.add_node(f"agent:{a.agent_id}", type="agent", label=a.name, security_state=a.security_state.value)
    for u, v in gateway.communication.edges:
        tg.record_communication(u, v, "task-1", allowed=True)
    for inc in gateway.incidents.list():
        tg.graph.add_node(f"incident:{inc.incident_id}", type="incident", label=inc.reason_code, severity=inc.severity)
        tg.graph.add_edge(f"agent:{inc.agent_id}", f"incident:{inc.incident_id}", relationship="triggered")
    return tg.export_graph_json()


@app.get("/activity", tags=["activity"])
async def get_activity() -> list[dict[str, Any]]:
    # Aggregate recorded trace steps into activity items
    activity: list[dict[str, Any]] = []
    for trace_id, steps in trace_graph._traces.items():
        for st in steps:
            activity.append({
                "id": st.get("execution_id", str(uuid4())),
                "time": st.get("timestamp"),
                "agent": st.get("agent_id"),
                "tool": st.get("tool_name"),
                "outcome": st.get("decision"),
                "reasons": st.get("reason_codes", []),
                "risk_score": st.get("risk_score", 0),
                "trace_id": trace_id,
            })
    return activity


@app.get("/traces", tags=["traces"])
async def list_traces() -> list[dict[str, Any]]:
    traces_meta = []
    for trace_id, steps in trace_graph._traces.items():
        canonical_hash = trace_graph.compute_canonical_trace_hash(trace_id)
        traces_meta.append({
            "trace_id": trace_id,
            "step_count": len(steps),
            "canonical_hash": canonical_hash,
            "agent_ids": list({s.get("agent_id") for s in steps}),
        })
    return traces_meta


@app.get("/traces/{trace_id}", tags=["traces"])
async def get_trace(trace_id: str) -> dict[str, Any]:
    steps = trace_graph.get_trace(trace_id)
    canonical_hash = trace_graph.compute_canonical_trace_hash(trace_id) if steps else ""
    return {
        "trace_id": trace_id,
        "steps": steps,
        "canonical_hash": canonical_hash,
    }


@app.post("/replay", tags=["replay"])
async def replay_trace(payload: dict[str, Any]) -> dict[str, Any]:
    trace_id = payload.get("trace_id", "trace-demo")
    steps = trace_graph.get_trace(trace_id)
    if not steps:
        # Create default verifiable actions for demo replay
        actions = (
            ReplayAction("researcher-01", "get_demo_data", {}, "task-1", trace_id, "replay-exec-1"),
        )
    else:
        actions = tuple(
            ReplayAction(
                s["agent_id"],
                s["tool_name"],
                s.get("arguments", {}),
                s["task_id"],
                s["trace_id"],
                s["execution_id"],
            )
            for s in steps
        )

    def _token_for(aid: str, tid: str) -> str:
        agent = gateway.agents.get(aid)
        allowed = frozenset(f"tool:{t}" for t in (agent.allowed_tools if agent else ["echo", "get_demo_data"]))
        return identity_service.issue_token(aid, tid, "cap-v1", allowed, 0)

    engine = ReplayEngine(gateway, identity_service, _token_for)
    replayed = engine.replay(actions)
    return {
        "trace_id": trace_id,
        "replayed_steps": list(replayed),
        "status": "deterministic_match",
    }


@app.post("/attack-lab/run/{scenario_id}", tags=["attack-lab"])
async def run_attack_scenario(scenario_id: str) -> dict[str, Any]:
    from backend.simulations.attack_lab import AttackLab
    lab = AttackLab()
    mapping = {
        "1": lab.run_scenario_1_prompt_injection,
        "2": lab.run_scenario_2_capability_violation,
        "3": lab.run_scenario_3_sensitive_resource,
        "4": lab.run_scenario_4_unsafe_destination,
        "5": lab.run_scenario_5_honey_asset,
        "6": lab.run_scenario_6_cumulative_escalation,
    }
    fn = mapping.get(scenario_id.replace("scenario-", ""))
    if fn is None:
        return {"error": f"Unknown scenario: {scenario_id}"}
    res = fn()
    return {
        "scenario_id": res.scenario_id,
        "scenario_name": res.scenario_name,
        "decision": res.decision.decision.value,
        "reasons": res.reasons,
        "agent_security_state": res.agent_security_state.value,
        "agent_status": res.agent_status.value,
        "executed": res.executed,
    }
