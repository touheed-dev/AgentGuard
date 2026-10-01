import os
from typing import Any

from fastapi import FastAPI
from pydantic import Field

from backend.apps.gateway.runtime import create_runtime
from backend.services.executor import AuthorizationReceipt
from backend.shared.contracts import ActionRequest, Decision, HealthResponse, StrictModel


class GatewayActionRequest(ActionRequest):
    token: str = Field(min_length=1)


class ExecutionResponse(StrictModel):
    decision: Decision
    result: dict[str, Any] | None = None


app = FastAPI(
    title="AgentGuard Gateway",
    version="0.1.0",
    description="Phase 1 deterministic security Gateway.",
)

gateway, identity_service, executor = create_runtime()


@app.get("/health", response_model=HealthResponse, tags=["system"])
async def health() -> HealthResponse:
    return HealthResponse(status="ok", mode=os.getenv("LLM_MODE", "replay"))


@app.post("/actions/evaluate", response_model=Decision, tags=["actions"])
async def evaluate_action(request: GatewayActionRequest) -> Decision:
    return gateway.authorize(
        request.agent_id,
        request.tool_name,
        request.arguments,
        request.task_id,
        request.trace_id,
        request.token,
        request.execution_id,
    )


@app.post("/actions/execute", response_model=ExecutionResponse, tags=["actions"])
async def execute_action(request: GatewayActionRequest) -> ExecutionResponse:
    decision = await evaluate_action(request)
    if decision.decision.value not in {"ALLOW", "WARN"}:
        return ExecutionResponse(decision=decision)
    result = executor.execute(executor.issue_grant(
        AuthorizationReceipt(
            decision=decision.decision,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            arguments=request.arguments,
            execution_id=decision.execution_id,
        )
    ))
    return ExecutionResponse(decision=decision, result=result)
