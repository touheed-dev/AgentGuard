"""AgentGuard Controlled Executor — Real Tool Execution.

The RealExecutor is the execution boundary between the Gateway
authorization decision and actual tool execution.

Security architecture:
  1. The Gateway calls issue_grant() with a Gateway-signed receipt.
  2. Only the Gateway holds the executor_issuer sentinel — no other
     code can issue grants.
  3. The executor verifies the grant fingerprint before executing.
  4. Each grant is single-use: the grant_id is deleted after use.
  5. Grants are bound to: decision, agent_id, tool_name, arguments,
     and execution_id — any modification invalidates the grant.

This ensures the Gateway is the actual enforcement boundary, not
merely a logging layer.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import uuid4

from backend.shared.contracts import AuthorizationReceipt, DecisionOutcome


class UnknownExecutionError(Exception):
    """Raised when execution outcome cannot be reliably determined (e.g. timeout, crash)."""
    pass


class StubExecutor:
    """Legacy stub executor — retained for backward compatibility with existing tests.

    In production, use RealExecutor or GatewayExecutor.
    """

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


class RealExecutor:
    """Gateway-controlled executor with real tool dispatch.

    Replaces StubExecutor for actual tool execution.  Maintains all the
    same grant-verification invariants:
      - Only the Gateway can issue grants (sentinel object check)
      - Single-use grants (deleted after execution)
      - Fingerprint binding (decision + agent + tool + args + exec_id)
      - ALLOW/WARN-only execution (BLOCK/REQUIRE_APPROVAL cannot execute)
    """

    def __init__(self, issuer: object) -> None:
        self._issuer = issuer
        self.execution_count = 0
        self._grants: dict[str, str] = {}
        self.force_unknown = False
        self.force_failure = False

    def issue_grant(self, receipt: AuthorizationReceipt, issuer: object) -> AuthorizationReceipt:
        """Issue a single-use execution grant.

        Only callable with the Gateway's private issuer sentinel.
        """
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
        """Execute the tool bound to this authorized receipt.

        Raises PermissionError if the receipt is invalid, forged,
        expired (already used), or has a mismatched fingerprint.
        """
        expected = self._grants.get(receipt.grant_id)
        if (
            receipt.decision not in {DecisionOutcome.ALLOW, DecisionOutcome.WARN}
            or expected is None
            or expected != self._fingerprint(receipt)
        ):
            raise PermissionError("Only Gateway-issued ALLOW and WARN receipts may reach execution.")

        # Single-use: remove before executing to prevent replay
        del self._grants[receipt.grant_id]

        self.execution_count += 1

        if self.force_unknown:
            raise UnknownExecutionError("Execution outcome cannot be reliably determined.")
        if self.force_failure:
            raise RuntimeError("Executor forced failure mode.")

        # Dispatch to real tool handlers
        from backend.core.tools.handlers import execute_tool
        try:
            return execute_tool(receipt.tool_name, receipt.arguments)
        except ValueError as exc:
            # Unknown tool — should have been caught by gateway tool registry
            raise RuntimeError(f"Tool handler error: {exc}") from exc

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
