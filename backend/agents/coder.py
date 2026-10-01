from backend.agents.base import ScriptedAgent


class Coder(ScriptedAgent):
    def __init__(self) -> None:
        super().__init__("coder-01", "echo", {"value": "coder result"})
