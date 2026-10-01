from typing import Protocol

from backend.shared.contracts import AgentProposal


class ProposalAgent(Protocol):
    agent_id: str

    def propose(self, task_id: str, trace_id: str) -> AgentProposal: ...


class ScriptedAgent:
    def __init__(self, agent_id: str, tool_name: str, arguments: dict[str, object]) -> None:
        self.agent_id = agent_id
        self.tool_name = tool_name
        self.arguments = arguments

    def propose(self, task_id: str, trace_id: str) -> AgentProposal:
        return AgentProposal(
            proposed_tool=self.tool_name,
            arguments=self.arguments,
            source="scripted",
            confidence=1.0,
            agent_id=self.agent_id,
            task_id=task_id,
            trace_id=trace_id,
        )
