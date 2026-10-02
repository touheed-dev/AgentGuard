"""AgentGuard SDK — Typed result models.

These models represent the structured response that the SDK returns
after every gateway interaction.  They are derived from the existing
Gateway decision contract (backend/shared/contracts.py) and must never
contain authorization logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class ExecutionStatus(StrEnum):
    SUCCESS = "SUCCESS"
    NOT_EXECUTED = "NOT_EXECUTED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ExecutionDetail:
    status: ExecutionStatus
    result: dict[str, Any] | None = None


@dataclass(frozen=True)
class AgentGuardResult:
    """Structured result returned by ``AgentGuard.execute()``.

    The Gateway is the authoritative source for every field here.
    The SDK only parses and wraps the Gateway response.

    Attributes
    ----------
    trace_id : str
        Unique trace identifier linking to dashboard / audit system.
    decision : Decision
        The Gateway's security verdict.
    reason_codes : list[str]
        Machine-readable reasons attached to the decision.
    execution : ExecutionDetail
        Status and result of the tool execution (only populated on ALLOW/WARN).
    risk : dict
        Raw risk assessment from the Gateway.
    approval_id : str | None
        Populated when decision == REQUIRE_APPROVAL.
    """

    trace_id: str
    decision: Decision
    reason_codes: list[str] = field(default_factory=list)
    execution: ExecutionDetail = field(default_factory=lambda: ExecutionDetail(ExecutionStatus.NOT_EXECUTED))
    risk: dict[str, Any] = field(default_factory=dict)
    approval_id: str | None = None
    execution_id: str = ""

    @property
    def allowed(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.WARN)

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK

    @property
    def requires_approval(self) -> bool:
        return self.decision == Decision.REQUIRE_APPROVAL


@dataclass(frozen=True)
class EvaluateResult:
    """Structured result returned by ``AgentGuard.evaluate()``.

    Dry-run evaluation: the Gateway determines whether the action would
    be allowed without actually executing the tool.
    """

    trace_id: str
    decision: Decision
    reason_codes: list[str] = field(default_factory=list)
    risk: dict[str, Any] = field(default_factory=dict)
    message: str = ""


@dataclass(frozen=True)
class AgentStatus:
    """Current agent state from ``AgentGuard.get_agent_status()``."""

    agent_id: str
    status: str
    security_state: str
    task_id: str
    allowed_tools: list[str] = field(default_factory=list)
    security_epoch: int = 0


@dataclass(frozen=True)
class TraceStep:
    agent_id: str
    tool_name: str
    task_id: str
    decision: str
    risk_score: float
    timestamp: str
    execution_id: str
    reason_codes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TraceResult:
    """Full trace record from ``AgentGuard.get_trace()``."""

    trace_id: str
    steps: list[TraceStep] = field(default_factory=list)
    canonical_hash: str = ""
