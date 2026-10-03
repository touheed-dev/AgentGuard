from dataclasses import dataclass

from backend.core.identity.models import Agent, AgentStatus, SecurityState
from backend.core.identity.service import VerifiedToken
from backend.shared.contracts import ReasonCode


@dataclass(frozen=True)
class CapabilityResult:
    allowed: bool
    code: ReasonCode | None = None
    message: str = ""


class CapabilityService:
    def check(
        self,
        agent: Agent,
        token: VerifiedToken,
        tool_name: str,
        task_id: str,
        known_tools: frozenset[str] = frozenset(),
        required_capability: str | None = None,
    ) -> CapabilityResult:
        if token.agent_id != agent.agent_id or token.task_id != task_id or agent.task_id != task_id:
            return CapabilityResult(False, ReasonCode.TOKEN_INVALID, "Token identity or task binding is invalid.")
        if agent.status in {AgentStatus.DISABLED, AgentStatus.SUSPENDED, AgentStatus.PAUSED, AgentStatus.RETIRED}:
            return CapabilityResult(False, ReasonCode.AGENT_DISABLED, "Agent is not active.")
        if agent.security_state == SecurityState.QUARANTINED:
            return CapabilityResult(False, ReasonCode.AGENT_QUARANTINED, "Agent is quarantined.")
        if token.security_epoch != agent.security_epoch or token.capability_version != agent.capability_version:
            return CapabilityResult(False, ReasonCode.TOKEN_INVALID, "Token security epoch or capability version is stale.")
        if known_tools and tool_name not in known_tools:
            return CapabilityResult(True, message="Tool resolution is required.")
        if tool_name in agent.forbidden_tools or tool_name not in agent.allowed_tools:
            return CapabilityResult(False, ReasonCode.CAPABILITY_DENIED, "Agent capability does not permit this tool.")
        capability = required_capability or f"tool:{tool_name}"
        if capability not in agent.scopes or capability not in token.scope:
            return CapabilityResult(False, ReasonCode.CAPABILITY_DENIED, "Token scope does not permit this tool.")
        return CapabilityResult(True, message="Capability granted.")
