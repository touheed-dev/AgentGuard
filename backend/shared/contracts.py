from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DecisionOutcome(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class ExecutionState(StrEnum):
    REQUESTED = "REQUESTED"
    AUTHORIZED = "AUTHORIZED"
    BLOCKED = "BLOCKED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNKNOWN_RESULT = "UNKNOWN_RESULT"


class ReasonCode(StrEnum):
    CAPABILITY_DENIED = "CAPABILITY_DENIED"
    TOOL_UNREGISTERED = "TOOL_UNREGISTERED"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SENSITIVE_RESOURCE = "SENSITIVE_RESOURCE"
    DESTINATION_NOT_ALLOWLISTED = "DESTINATION_NOT_ALLOWLISTED"
    TASK_INCONSISTENT = "TASK_INCONSISTENT"
    COMM_PATH_DENIED = "COMM_PATH_DENIED"
    HONEY_ASSET_TOUCHED = "HONEY_ASSET_TOUCHED"
    CUMULATIVE_RISK_HIGH = "CUMULATIVE_RISK_HIGH"
    BREAKER_TRIPPED = "BREAKER_TRIPPED"
    REQUEST_REPLAYED = "REQUEST_REPLAYED"
    TOKEN_INVALID = "TOKEN_INVALID"
    APPROVAL_STALE = "APPROVAL_STALE"
    EXECUTION_DUPLICATE = "EXECUTION_DUPLICATE"
    RESULT_UNKNOWN = "RESULT_UNKNOWN"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HealthResponse(StrictModel):
    status: str
    mode: str


class AgentProposal(StrictModel):
    proposed_tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    source: str
    confidence: float = Field(ge=0, le=1)


class ActionRequest(StrictModel):
    request_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    task_id: str = Field(min_length=1)
    trace_id: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    lifecycle_state: ExecutionState = ExecutionState.REQUESTED


class Reason(StrictModel):
    code: ReasonCode
    message: str
    severity: str
    source: str


class Decision(StrictModel):
    decision: DecisionOutcome
    reasons: tuple[Reason, ...] = ()
    risk: dict[str, Any] = Field(default_factory=dict)
    policy_results: dict[str, Any] = Field(default_factory=dict)
    capability_result: dict[str, Any] = Field(default_factory=dict)
    parameter_result: dict[str, Any] = Field(default_factory=dict)
