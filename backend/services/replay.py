from dataclasses import dataclass
import hashlib
from typing import Any

import rfc8785
from backend.core.gateway import Gateway
from backend.core.identity.service import IdentityService


@dataclass(frozen=True)
class ReplayAction:
    agent_id: str
    tool_name: str
    arguments: dict[str, Any]
    task_id: str
    trace_id: str
    execution_id: str


class ReplayEngine:
    def __init__(self, gateway: Gateway, identity: IdentityService, token_for) -> None:
        self.gateway = gateway
        self.identity = identity
        self.token_for = token_for

    def replay(self, actions: tuple[ReplayAction, ...]) -> tuple[dict[str, Any], ...]:
        self.gateway.reset_replay_state()
        results: list[dict[str, Any]] = []
        for action in actions:
            decision = self.gateway.authorize(
                action.agent_id,
                action.tool_name,
                action.arguments,
                action.task_id,
                action.trace_id,
                self.token_for(action.agent_id, action.task_id),
                action.execution_id,
                f"{action.trace_id}-request-{action.execution_id}",
            )
            results.append({"execution_id": action.execution_id, "decision": decision.model_dump(mode="json"), "result": None})
        trace_inputs = [
            {
                "agent_id": action.agent_id,
                "tool_name": action.tool_name,
                "arguments": action.arguments,
                "task_id": action.task_id,
                "trace_id": action.trace_id,
                "execution_id": action.execution_id,
                "decision": result["decision"],
            }
            for action, result in zip(actions, results)
        ]
        normalized = hashlib.sha256(rfc8785.dumps(trace_inputs)).hexdigest()
        return tuple({**result, "normalized_trace_hash": normalized} for result in results)
