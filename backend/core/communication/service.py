from dataclasses import dataclass
from typing import Any

from backend.core.identity.models import Agent, AgentStatus, SecurityState
from backend.core.identity.registry import AgentRegistry
from backend.shared.contracts import ReasonCode


@dataclass(frozen=True)
class CommunicationResult:
    allowed: bool
    code: ReasonCode | None = None
    reason: str = ""


class CommunicationService:
    def __init__(
        self,
        edges: frozenset[tuple[str, str]] = frozenset(),
        agents: AgentRegistry | None = None,
    ) -> None:
        self.edges = edges
        self.agents = agents

    def authorize(
        self,
        sender_id: str,
        recipient_id: str,
        task_id: str | None = None,
        capability: str | None = None,
    ) -> CommunicationResult:
        if self.agents is not None:
            sender = self.agents.get(sender_id)
            if sender is None:
                return CommunicationResult(False, ReasonCode.TOKEN_INVALID, f"Sender agent '{sender_id}' is not registered.")
            if sender.status in {AgentStatus.DISABLED, AgentStatus.SUSPENDED, AgentStatus.PAUSED, AgentStatus.RETIRED}:
                return CommunicationResult(False, ReasonCode.AGENT_DISABLED, f"Sender agent '{sender_id}' is disabled or suspended.")
            if sender.security_state == SecurityState.QUARANTINED:
                return CommunicationResult(False, ReasonCode.AGENT_QUARANTINED, f"Sender agent '{sender_id}' is quarantined.")

            recipient = self.agents.get(recipient_id)
            if recipient is None:
                return CommunicationResult(False, ReasonCode.COMM_PATH_DENIED, f"Recipient agent '{recipient_id}' is not registered.")
            if recipient.status in {AgentStatus.DISABLED, AgentStatus.SUSPENDED, AgentStatus.PAUSED, AgentStatus.RETIRED}:
                return CommunicationResult(False, ReasonCode.AGENT_DISABLED, f"Recipient agent '{recipient_id}' is disabled or suspended.")
            if recipient.security_state == SecurityState.QUARANTINED:
                return CommunicationResult(False, ReasonCode.AGENT_QUARANTINED, f"Recipient agent '{recipient_id}' is quarantined.")

            if task_id is not None:
                if sender.task_id != task_id or recipient.task_id != task_id:
                    return CommunicationResult(False, ReasonCode.COMM_PATH_DENIED, f"Task mismatch: sender/recipient task differs from '{task_id}'.")

            if capability is not None:
                if capability not in sender.scopes:
                    return CommunicationResult(False, ReasonCode.CAPABILITY_DENIED, f"Sender lacks communication capability '{capability}'.")

        if (sender_id, recipient_id) not in self.edges:
            return CommunicationResult(False, ReasonCode.COMM_PATH_DENIED, f"Communication path '{sender_id}' -> '{recipient_id}' is not allowlisted.")

        return CommunicationResult(True, None, "Communication path authorized.")
