from backend.agents.base import ScriptedAgent


class Planner(ScriptedAgent):
    def __init__(self) -> None:
        super().__init__("planner-01", "echo", {"value": "planner proposal"})
