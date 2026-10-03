from dataclasses import dataclass
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


class EventType(StrEnum):
    ACTION_AUTHORIZED = "agent.action.authorized"
    ACTION_BLOCKED = "agent.action.blocked"
    ACTION_EXECUTING = "agent.action.executing"
    ACTION_SUCCEEDED = "agent.action.succeeded"
    ACTION_FAILED = "agent.action.failed"
    ACTION_CANCELLED = "agent.action.cancelled"
    ACTION_UNKNOWN_RESULT = "agent.action.unknown_result"


class ReasonCode(StrEnum):
    AGENT_DISABLED = "AGENT_DISABLED"
    AGENT_QUARANTINED = "AGENT_QUARANTINED"
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
    THREAT_INTEL_MALICIOUS = "THREAT_INTEL_MALICIOUS"
    THREAT_INTEL_SUSPICIOUS = "THREAT_INTEL_SUSPICIOUS"


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
    agent_id: str = ""
    task_id: str = ""
    trace_id: str = ""


@dataclass(frozen=True)
class AuthorizationReceipt:
    decision: DecisionOutcome
    agent_id: str
    tool_name: str
    arguments: dict[str, Any]
    execution_id: str
    grant_id: str = ""


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
    approval_id: str | None = None


class Reason(StrictModel):
    code: ReasonCode
    message: str
    severity: str
    source: str


class Decision(StrictModel):
    decision: DecisionOutcome
    agent_id: str = ""
    tool_name: str = ""
    task_id: str = ""
    trace_id: str = ""
    execution_id: str = ""
    reasons: tuple[Reason, ...] = ()
    risk: dict[str, Any] = Field(default_factory=dict)
    policy_results: dict[str, Any] = Field(default_factory=dict)
    capability_result: dict[str, Any] = Field(default_factory=dict)
    parameter_result: dict[str, Any] = Field(default_factory=dict)
