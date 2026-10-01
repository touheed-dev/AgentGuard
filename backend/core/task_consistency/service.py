from enum import StrEnum

from backend.shared.contracts import StrictModel


class Consistency(StrEnum):
    CONSISTENT = "CONSISTENT"
    SUSPICIOUS = "SUSPICIOUS"
    INCONSISTENT = "INCONSISTENT"


class TaskDefinition(StrictModel):
    task_id: str
    label: str
    allowed_tools: frozenset[str]


class TaskConsistencyService:
    def __init__(self, tasks: tuple[TaskDefinition, ...] = ()) -> None:
        self._tasks = {task.task_id: task for task in tasks}

    def evaluate(self, task_id: str, tool_name: str) -> Consistency:
        task = self._tasks.get(task_id)
        if task is not None and tool_name in task.allowed_tools:
            return Consistency.CONSISTENT
        return Consistency.SUSPICIOUS
