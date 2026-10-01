from backend.agents.base import ScriptedAgent


class Executor(ScriptedAgent):
    def __init__(self) -> None:
        super().__init__("executor-01", "echo", {"value": "executor result"})
