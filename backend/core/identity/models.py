from enum import StrEnum

from pydantic import Field

from backend.shared.contracts import StrictModel


class AgentStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class SecurityState(StrEnum):
    CLEAN = "CLEAN"
    TRUSTED = "TRUSTED"
    SUSPECTED = "SUSPECTED"
    COMPROMISED = "COMPROMISED"
    QUARANTINED = "QUARANTINED"
    RECOVERED = "RECOVERED"


class Agent(StrictModel):
    agent_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    status: AgentStatus = AgentStatus.ACTIVE
    security_state: SecurityState = SecurityState.CLEAN
    capability_version: str = Field(min_length=1)
    allowed_tools: frozenset[str] = frozenset()
    forbidden_tools: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    task_id: str = Field(min_length=1)
    security_epoch: int = Field(default=0, ge=0)
