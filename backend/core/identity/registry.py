from backend.core.identity.models import Agent


class AgentRegistry:
    def __init__(self, agents: tuple[Agent, ...] = ()) -> None:
        self._agents = {agent.agent_id: agent for agent in agents}

    def register(self, agent: Agent) -> None:
        self._agents = {**self._agents, agent.agent_id: agent}

    def get(self, agent_id: str) -> Agent | None:
        return self._agents.get(agent_id)

    def replace(self, agent: Agent) -> None:
        if agent.agent_id not in self._agents:
            raise KeyError(agent.agent_id)
        self.register(agent)
