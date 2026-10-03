import hashlib
import json
from typing import Any
from uuid import uuid4

from backend.shared.contracts import AuthorizationReceipt, DecisionOutcome


class UnknownExecutionError(Exception):
    """Raised when execution outcome cannot be reliably determined (e.g. timeout, crash)."""
    pass


class StubExecutor:
    def __init__(self, issuer: object) -> None:
        self._issuer = issuer
        self.execution_count = 0
        self._grants: dict[str, str] = {}
        self.force_unknown = False
        self.force_failure = False

    def issue_grant(self, receipt: AuthorizationReceipt, issuer: object) -> AuthorizationReceipt:
        if issuer is not self._issuer:
            raise PermissionError("Only the Gateway may issue executor grants.")
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
        if self.force_unknown:
            raise UnknownExecutionError("Execution outcome cannot be reliably determined.")
        if self.force_failure:
            raise RuntimeError("Stub execution failed with an explicit error.")
        if receipt.tool_name == "echo":
            return {"tool": "echo", "value": receipt.arguments.get("value")}
        if receipt.tool_name == "get_demo_data":
            return {"tool": "get_demo_data", "data": ["synthetic-alpha", "synthetic-beta"]}
        if receipt.tool_name in {"read_file", "file_read"}:
            return {"tool": receipt.tool_name, "content": "synthetic file contents", "executed": True}
        if receipt.tool_name == "search_knowledge":
            return {"tool": "search_knowledge", "results": [{"title": "agentguard", "content": "zero-trust security"}], "executed": True}
        return {"tool": receipt.tool_name, "status": "executed", "executed": True, "arguments": receipt.arguments}

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
