from backend.agents.base import ScriptedAgent


class Researcher(ScriptedAgent):
    def __init__(self) -> None:
        super().__init__("researcher-01", "get_demo_data", {})
