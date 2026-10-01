import os
from typing import Any

from fastapi import FastAPI
from pydantic import Field

from backend.apps.gateway.runtime import create_runtime
from backend.services.executor import AuthorizationReceipt
from backend.services.persistence import PersistenceCoordinator
from backend.shared.contracts import ActionRequest, Decision, DecisionOutcome, HealthResponse, Reason, ReasonCode, StrictModel


class GatewayActionRequest(ActionRequest):
    token: str = Field(min_length=1)


class ExecutionResponse(StrictModel):
    decision: Decision
    result: dict[str, Any] | None = None


class AuditVerificationResponse(StrictModel):
    verified: bool
    checked_events: int
    error: str | None = None


app = FastAPI(
    title="AgentGuard Gateway",
    version="0.1.0",
    description="Phase 1 deterministic security Gateway.",
)

gateway, identity_service, executor = create_runtime()
persistence = PersistenceCoordinator() if os.getenv("AGENTGUARD_PERSISTENCE", "false").lower() == "true" else None


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    return HealthResponse(status="ok", mode=os.getenv("LLM_MODE", "replay"))


@app.post("/actions/evaluate", response_model=Decision, tags=["actions"])
async def evaluate_action(request: GatewayActionRequest) -> Decision:
    decision = gateway.authorize(
        request.agent_id,
        request.tool_name,
        request.arguments,
        request.task_id,
        request.trace_id,
        request.token,
        request.execution_id,
    )
    if persistence is not None:
            persisted = await persistence.persist_authorization(request, decision)
            if persisted.conflict:
                return Decision(
                    decision=DecisionOutcome.BLOCK,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    task_id=request.task_id,
                    trace_id=request.trace_id,
                    execution_id=request.execution_id,
                    reasons=(Reason(code=ReasonCode.EXECUTION_DUPLICATE, message="Idempotency key conflicts with an existing execution.", severity="critical", source="persistence"),),
                )
    return decision


@app.post("/actions/execute", response_model=ExecutionResponse, tags=["actions"])
async def execute_action(request: GatewayActionRequest) -> ExecutionResponse:
    decision = await evaluate_action(request)
    if decision.decision.value not in {"ALLOW", "WARN"}:
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
        result = executor.execute(executor.issue_grant(
            AuthorizationReceipt(
                decision=decision.decision,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                arguments=request.arguments,
                execution_id=decision.execution_id,
            )
        ))
    except Exception:
        if persistence is not None:
            await persistence.persist_result(request, decision, "FAILED")
        raise
    if persistence is not None:
        await persistence.persist_result(request, decision, "SUCCEEDED", result)
    return ExecutionResponse(decision=decision, result=result)


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
