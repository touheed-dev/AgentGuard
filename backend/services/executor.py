from dataclasses import dataclass
import hashlib
import json
from typing import Any
from uuid import uuid4

from backend.shared.contracts import DecisionOutcome


@dataclass(frozen=True)
class AuthorizationReceipt:
    decision: DecisionOutcome
    agent_id: str
    tool_name: str
    arguments: dict[str, Any]
    execution_id: str
    grant_id: str = ""


class StubExecutor:
    def __init__(self) -> None:
        self.execution_count = 0
        self._grants: dict[str, str] = {}

    def issue_grant(self, receipt: AuthorizationReceipt) -> AuthorizationReceipt:
        grant_id = str(uuid4())
        granted = AuthorizationReceipt(
            receipt.decision,
            receipt.agent_id,
            receipt.tool_name,
            receipt.arguments,
            receipt.execution_id,
            grant_id,
        )
        self._grants[grant_id] = self._fingerprint(granted)
        return granted

    def execute(self, receipt: AuthorizationReceipt) -> dict[str, Any]:
        expected = self._grants.get(receipt.grant_id)
        if (
            receipt.decision not in {DecisionOutcome.ALLOW, DecisionOutcome.WARN}
            or expected is None
            or expected != self._fingerprint(receipt)
        ):
            raise PermissionError("Only Gateway-issued ALLOW and WARN receipts may reach execution.")
        del self._grants[receipt.grant_id]
        self.execution_count += 1
        if receipt.tool_name == "echo":
            return {"tool": "echo", "value": receipt.arguments.get("value")}
        if receipt.tool_name == "get_demo_data":
            return {"tool": "get_demo_data", "data": ["synthetic-alpha", "synthetic-beta"]}
        raise ValueError(f"No stub implementation for {receipt.tool_name}.")

    @staticmethod
    def _fingerprint(receipt: AuthorizationReceipt) -> str:
        payload = json.dumps(
            [
                receipt.decision.value,
                receipt.agent_id,
                receipt.tool_name,
                receipt.arguments,
                receipt.execution_id,
            ],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
