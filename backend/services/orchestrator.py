from dataclasses import dataclass
from typing import Any, Callable

from backend.agents.base import ProposalAgent
from backend.core.gateway import Gateway
from backend.core.identity.service import IdentityService
from backend.shared.contracts import Decision


@dataclass(frozen=True)
class TraceStep:
    agent_id: str
    tool_name: str
    task_id: str
    trace_id: str
    execution_id: str
    decision: Decision
    result: dict[str, Any] | None
    proposal_source: str
    proposal_confidence: float


class Orchestrator:
    def __init__(self, gateway: Gateway, identity: IdentityService, token_for: Callable[[str, str], str]) -> None:
        self.gateway = gateway
        self.identity = identity
        self.token_for = token_for

    def run(self, agents: tuple[ProposalAgent, ...], task_id: str, trace_id: str) -> tuple[TraceStep, ...]:
        steps: list[TraceStep] = []
        for index, agent in enumerate(agents, start=1):
            proposal = agent.propose(task_id, trace_id)
            if proposal.agent_id != agent.agent_id or proposal.task_id != task_id or proposal.trace_id != trace_id:
                raise ValueError("Proposal identity does not match the orchestrator context.")
            execution_id = f"{trace_id}-execution-{index}"
            token = self.token_for(agent.agent_id, task_id)
            decision, result = self.gateway.execute(
                agent.agent_id,
                proposal.proposed_tool,
                proposal.arguments,
                task_id,
                trace_id,
                token,
                execution_id,
                f"{trace_id}-request-{index}",
            )
            steps.append(TraceStep(agent.agent_id, proposal.proposed_tool, task_id, trace_id, execution_id, decision, result, proposal.source, proposal.confidence))
        return tuple(steps)
