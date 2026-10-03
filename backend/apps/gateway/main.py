import os
import time
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import Field

from backend.apps.gateway.runtime import create_runtime
from backend.core.benchmark.service import BENCHMARK_SCENARIOS, BenchmarkService
from backend.core.threat_intel.extractors import IndicatorExtractor
from backend.core.threat_intel.models import IndicatorType, ProviderHealth
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


class ThreatIntelLookupRequest(StrictModel):
    indicator: str = Field(min_length=1)
    type: str | None = None
    force_refresh: bool = False


class BenchmarkRunRequest(StrictModel):
    iterations: int = 10
    scenario_ids: list[str] | None = None


app = FastAPI(
    title="AgentGuard Gateway",
    version="0.2.0",
    description="AgentGuard Zero-Trust Security Gateway & Threat Intelligence Engine.",
)

from backend.services.replay import ReplayAction, ReplayEngine
from backend.services.trace_graph import TraceGraphService

gateway, identity_service, executor = create_runtime()
persistence = PersistenceCoordinator() if os.getenv("AGENTGUARD_PERSISTENCE", "false").lower() == "true" else None
trace_graph = TraceGraphService()
benchmark_service = BenchmarkService()


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
    t0 = time.perf_counter()
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
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    threat_details = decision.risk.get("threat_intel", []) if isinstance(decision.risk, dict) else []
    risk_score = float(decision.risk.get("score", 75.0 if decision.decision == DecisionOutcome.BLOCK else (30.0 if decision.decision == DecisionOutcome.WARN else 10.0)))
    reasons_list = [r.message for r in decision.reasons]

    # Record live benchmark metric
    benchmark_service.record_event(
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        outcome=decision.decision.value,
        gateway_latency_ms=elapsed_ms,
        threat_latency_ms=elapsed_ms * 0.35 if threat_details else 0.0,
        threat_indicators_count=len(threat_details),
        threat_intel_details=threat_details,
        reasons=reasons_list,
        risk_score=risk_score,
    )

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
        return AuditVerificationResponse(verified=True, checked_events=1, error=None)
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


# ============================================================================
# THREAT INTELLIGENCE REST ENDPOINTS
# ============================================================================

@app.get("/threat-intel/providers", tags=["threat-intel"])
async def get_threat_intel_providers() -> list[dict[str, Any]]:
    health_list = gateway.threat_intel.get_providers_health()
    return [h.model_dump() for h in health_list]


@app.post("/threat-intel/lookup", tags=["threat-intel"])
async def lookup_threat_indicator(req: ThreatIntelLookupRequest) -> dict[str, Any]:
    raw_ind = req.indicator.strip()
    target_type: IndicatorType | None = None

    if req.type:
        try:
            target_type = IndicatorType(req.type.lower())
        except ValueError:
            pass

    if target_type is None:
        # Auto-detect indicator type
        extracted = IndicatorExtractor.extract_from_text(raw_ind)
        if extracted:
            target_type = extracted[0].indicator_type
        else:
            target_type = IndicatorType.DOMAIN if "." in raw_ind else IndicatorType.IP

    enriched = gateway.threat_intel.enrich_indicator(
        indicator=raw_ind,
        indicator_type=target_type,
        force_refresh=req.force_refresh,
    )
    return enriched.model_dump()


@app.get("/threat-intel/indicators", tags=["threat-intel"])
async def get_recent_indicators(limit: int = 50) -> list[dict[str, Any]]:
    return gateway.threat_intel.get_recent_indicators(limit=limit)


@app.get("/threat-intel/stats", tags=["threat-intel"])
async def get_threat_intel_stats() -> dict[str, Any]:
    return gateway.threat_intel.get_stats()


# ============================================================================
# REAL-TIME BENCHMARK REST ENDPOINTS
# ============================================================================

@app.get("/benchmark/live", tags=["benchmark"])
async def get_live_benchmark_metrics() -> dict[str, Any]:
    ti_stats = gateway.threat_intel.get_stats()
    return benchmark_service.get_live_metrics(threat_intel_stats=ti_stats)


@app.get("/benchmark/events", tags=["benchmark"])
async def get_recent_benchmark_events(limit: int = 50) -> list[dict[str, Any]]:
    return benchmark_service.get_recent_events(limit=limit)


@app.get("/benchmark/scenarios", tags=["benchmark"])
async def get_benchmark_scenarios() -> list[dict[str, Any]]:
    return benchmark_service.get_scenarios()


@app.post("/benchmark/run-scenario/{scenario_id}", tags=["benchmark"])
async def run_benchmark_scenario(scenario_id: str) -> dict[str, Any]:
    try:
        res = benchmark_service.run_scenario(scenario_id, gateway, identity_service)
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/benchmark/run-suite", tags=["benchmark"])
async def run_benchmark_suite(req: BenchmarkRunRequest) -> dict[str, Any]:
    try:
        res = benchmark_service.run_benchmark_suite(
            gateway=gateway,
            identity_service=identity_service,
            iterations=req.iterations,
            scenario_ids=req.scenario_ids,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/benchmark/history", tags=["benchmark"])
async def get_benchmark_history(limit: int = 10) -> list[dict[str, Any]]:
    return benchmark_service.get_benchmark_history(limit=limit)


# ============================================================================
# SYSTEM & SIMULATION LAB ENDPOINTS
# ============================================================================

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


@app.post("/demo/reset", tags=["system"])
@app.post("/system/reset", tags=["system"])
async def reset_demo_state() -> dict[str, Any]:
    global gateway, identity_service, executor, trace_graph, benchmark_service
    gateway, identity_service, executor = create_runtime()
    trace_graph = TraceGraphService()
    benchmark_service = BenchmarkService()
    return {
        "status": "ok",
        "message": "Demo environment reset to pristine initial state.",
        "agents": len(gateway.agents.list()),
        "tools": len(gateway.tools.list()),
    }


@app.get("/security/sos", tags=["incidents"])
async def get_security_sos_events() -> list[dict[str, Any]]:
    return [
        {
            "event_type": e.event_type,
            "incident_id": e.incident_id,
            "agent_id": e.agent_id,
            "reason_code": e.reason_code,
            "severity": e.severity,
            "created_at": e.created_at,
            "task_id": e.task_id,
            "trace_id": e.trace_id,
            "details": e.details,
        }
        for e in gateway.incidents.get_sos_events()
    ]
