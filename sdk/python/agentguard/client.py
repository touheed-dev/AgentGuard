"""AgentGuard SDK — Client.

The SDK is a THIN integration layer.  It MUST NOT contain:
  - CEL policy logic
  - authorization logic
  - capability decisions
  - risk calculations
  - honeytoken decisions
  - quarantine decisions
  - final security decisions

All security decisions are made by the AgentGuard Gateway.

Usage
-----
    from agentguard import AgentGuard

    guard = AgentGuard(
        gateway="http://localhost:8000",
        agent_id="researcher-01",
        token=TOKEN,
    )

    result = guard.execute(
        tool="read_file",
        parameters={"path": "/data/report.pdf"},
        task_id="task-001",
    )
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

try:
    import httpx as _httpx_mod
    _httpx_available = True
except ImportError:
    _httpx_available = False

try:
    import urllib.request as _urllib_request
    import json as _json_mod
    _urllib_available = True
except ImportError:
    _urllib_available = False

from agentguard.exceptions import (
    AgentGuardError,
    ApprovalRequiredError,
    AuthenticationError,
    BlockedActionError,
    ConnectionError,
    ExecutionError,
    MalformedResponseError,
    QuarantinedAgentError,
    TimeoutError,
    ValidationError,
)
from agentguard.models import (
    AgentStatus,
    Decision,
    EvaluateResult,
    ExecutionDetail,
    ExecutionStatus,
    AgentGuardResult,
    TraceResult,
    TraceStep,
)

logger = logging.getLogger("agentguard.sdk")

_QUARANTINE_REASON_CODES = frozenset({"AGENT_QUARANTINED", "BREAKER_TRIPPED"})


def _new_id(prefix: str = "") -> str:
    uid = str(uuid.uuid4())
    return f"{prefix}{uid}" if prefix else uid


class AgentGuard:
    """AgentGuard SDK client.

    The SDK is responsible for:
      - Gateway connection
      - Authentication headers
      - Request construction (request IDs, trace IDs, execution IDs)
      - Timeouts
      - Response parsing into typed models
      - Clean, typed exceptions for every Gateway outcome

    The SDK is NOT responsible for:
      - Making security decisions
      - Computing risk scores
      - Deciding capability
      - Honeytoken detection
      - Quarantine logic

    Parameters
    ----------
    gateway : str
        Base URL of the AgentGuard Gateway (e.g. ``"http://localhost:8000"``).
    agent_id : str
        Registered agent identity.
    token : str
        JWT bearer token issued by the Gateway ``/tokens/issue`` endpoint.
    task_id : str
        Default task scope for requests (can be overridden per-call).
    timeout : float
        HTTP request timeout in seconds (default 30).
    trace_id : str | None
        Optional fixed trace ID.  Auto-generated per-call if not provided.
    """

    def __init__(
        self,
        gateway: str,
        agent_id: str,
        token: str,
        task_id: str = "task-1",
        timeout: float = 30.0,
        trace_id: str | None = None,
    ) -> None:
        self.gateway = gateway.rstrip("/")
        self.agent_id = agent_id
        self._token = token
        self.task_id = task_id
        self.timeout = timeout
        self._default_trace_id = trace_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(
        self,
        tool: str,
        parameters: dict[str, Any] | None = None,
        task_id: str | None = None,
        trace_id: str | None = None,
        approval_id: str | None = None,
    ) -> AgentGuardResult:
        """Execute a tool action through the AgentGuard Gateway.

        The Gateway evaluates the action through its full 20-stage security
        pipeline.  If the decision is ALLOW or WARN, the Gateway itself
        executes the tool and returns the result.

        Parameters
        ----------
        tool : str
            Registered tool name (e.g. ``"read_file"``).
        parameters : dict | None
            Tool input parameters.
        task_id : str | None
            Task scope override; uses client default if not provided.
        trace_id : str | None
            Trace ID override; auto-generated if not provided.
        approval_id : str | None
            Approval record ID to attach for REQUIRE_APPROVAL actions.

        Returns
        -------
        AgentGuardResult

        Raises
        ------
        BlockedActionError
            Gateway returned BLOCK.  Tool was NOT executed.
        ApprovalRequiredError
            Gateway returned REQUIRE_APPROVAL.  Action is pending human review.
        QuarantinedAgentError
            Agent is quarantined.  All future actions will be blocked.
        AuthenticationError
            Token is invalid or expired.
        TimeoutError
            Gateway did not respond within ``timeout`` seconds.
        ConnectionError
            Gateway is unreachable.
        ExecutionError
            Tool was authorized but encountered a runtime error.
        MalformedResponseError
            Gateway returned an unrecognizable response.
        """
        tid = task_id or self.task_id
        trid = trace_id or self._default_trace_id or _new_id("trace-")
        request_id = _new_id("req-")
        execution_id = _new_id("exec-")
        idempotency_key = _new_id("ikey-")

        payload: dict[str, Any] = {
            "request_id": request_id,
            "execution_id": execution_id,
            "agent_id": self.agent_id,
            "tool_name": tool,
            "arguments": parameters or {},
            "task_id": tid,
            "trace_id": trid,
            "idempotency_key": idempotency_key,
            "token": self._token,
        }
        if approval_id:
            payload["approval_id"] = approval_id

        logger.debug(
            "SDK execute: agent=%s tool=%s task=%s trace=%s exec=%s",
            self.agent_id, tool, tid, trid, execution_id,
        )

        raw = self._post("/actions/execute", payload)
        return self._parse_execute_response(raw, trid, execution_id)

    def evaluate(
        self,
        tool: str,
        parameters: dict[str, Any] | None = None,
        task_id: str | None = None,
        trace_id: str | None = None,
    ) -> EvaluateResult:
        """Dry-run evaluation — check Gateway decision without executing.

        Useful for agents to pre-screen actions before committing.

        Returns
        -------
        EvaluateResult
        """
        tid = task_id or self.task_id
        trid = trace_id or self._default_trace_id or _new_id("trace-eval-")
        request_id = _new_id("req-eval-")
        execution_id = _new_id("exec-eval-")
        idempotency_key = _new_id("ikey-eval-")

        payload: dict[str, Any] = {
            "request_id": request_id,
            "execution_id": execution_id,
            "agent_id": self.agent_id,
            "tool_name": tool,
            "arguments": parameters or {},
            "task_id": tid,
            "trace_id": trid,
            "idempotency_key": idempotency_key,
            "token": self._token,
        }

        logger.debug("SDK evaluate: agent=%s tool=%s task=%s", self.agent_id, tool, tid)

        raw = self._post("/actions/evaluate", payload)
        return self._parse_evaluate_response(raw, trid)

    def get_agent_status(self) -> AgentStatus:
        """Retrieve current agent status from the Gateway registry.

        Returns
        -------
        AgentStatus
        """
        raw = self._get(f"/agents")
        try:
            agents = raw if isinstance(raw, list) else []
            for agent_data in agents:
                if agent_data.get("agent_id") == self.agent_id:
                    return AgentStatus(
                        agent_id=agent_data["agent_id"],
                        status=agent_data.get("status", "UNKNOWN"),
                        security_state=agent_data.get("security_state", "UNKNOWN"),
                        task_id=agent_data.get("task_id", ""),
                        allowed_tools=agent_data.get("allowed_tools", []),
                        security_epoch=agent_data.get("security_epoch", 0),
                    )
            # Agent not found — return minimal structure
            return AgentStatus(
                agent_id=self.agent_id,
                status="NOT_FOUND",
                security_state="UNKNOWN",
                task_id="",
            )
        except (KeyError, TypeError) as exc:
            raise MalformedResponseError(f"Could not parse agent status: {exc}") from exc

    def get_trace(self, trace_id: str) -> TraceResult:
        """Retrieve a full trace record for investigation.

        Parameters
        ----------
        trace_id : str

        Returns
        -------
        TraceResult
        """
        raw = self._get(f"/traces/{trace_id}")
        try:
            steps = [
                TraceStep(
                    agent_id=s.get("agent_id", ""),
                    tool_name=s.get("tool_name", ""),
                    task_id=s.get("task_id", ""),
                    decision=s.get("decision", "UNKNOWN"),
                    risk_score=float(s.get("risk_score", 0.0)),
                    timestamp=str(s.get("timestamp", "")),
                    execution_id=s.get("execution_id", ""),
                    reason_codes=s.get("reason_codes", []),
                )
                for s in raw.get("steps", [])
            ]
            return TraceResult(
                trace_id=trace_id,
                steps=steps,
                canonical_hash=raw.get("canonical_hash", ""),
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise MalformedResponseError(f"Could not parse trace: {exc}") from exc

    def issue_token(self, task_id: str | None = None, lifetime_seconds: int = 300) -> str:
        """Convenience: issue a new token via the Gateway (for testing/demo purposes).

        Returns the new token string.
        """
        tid = task_id or self.task_id
        payload = {
            "agent_id": self.agent_id,
            "task_id": tid,
            "lifetime_seconds": lifetime_seconds,
        }
        raw = self._post("/tokens/issue", payload)
        token = raw.get("token", "") if isinstance(raw, dict) else ""
        if not token:
            raise MalformedResponseError("Gateway did not return a token.")
        self._token = token
        return token

    # ------------------------------------------------------------------
    # Internal: response parsing
    # ------------------------------------------------------------------

    def _parse_execute_response(
        self,
        raw: dict[str, Any],
        trace_id: str,
        execution_id: str,
    ) -> AgentGuardResult:
        try:
            decision_raw = raw.get("decision", {})
            if isinstance(decision_raw, dict):
                outcome_str = decision_raw.get("decision", "BLOCK")
                reasons_raw = decision_raw.get("reasons", ())
                reason_codes = [r.get("code", "") if isinstance(r, dict) else str(r) for r in reasons_raw]
                risk = decision_raw.get("risk", {}) or {}
                resp_trace_id = decision_raw.get("trace_id", trace_id)
                resp_execution_id = decision_raw.get("execution_id", execution_id)
            else:
                outcome_str = str(decision_raw)
                reason_codes = []
                risk = {}
                resp_trace_id = trace_id
                resp_execution_id = execution_id

            try:
                outcome = Decision(outcome_str)
            except ValueError:
                outcome = Decision.BLOCK

            # Check for quarantine
            if any(rc in _QUARANTINE_REASON_CODES for rc in reason_codes) and outcome == Decision.BLOCK:
                pass  # Will be surfaced as BlockedActionError with QUARANTINED code below

            # Parse execution result
            exec_result_raw = raw.get("result")
            if outcome in (Decision.ALLOW, Decision.WARN) and exec_result_raw is not None:
                exec_detail = ExecutionDetail(
                    status=ExecutionStatus.SUCCESS,
                    result=exec_result_raw,
                )
            elif outcome == Decision.REQUIRE_APPROVAL:
                exec_detail = ExecutionDetail(status=ExecutionStatus.APPROVAL_PENDING)
            else:
                exec_detail = ExecutionDetail(status=ExecutionStatus.NOT_EXECUTED)

            # Extract approval_id from pending approvals if present
            approval_id: str | None = None
            if outcome == Decision.REQUIRE_APPROVAL:
                # The gateway creates an approval record; we surface trace_id + execution_id
                # The caller can look up approvals via the dashboard or /approvals endpoint
                approval_id = _resolve_approval_id(raw, resp_execution_id)

            result = AgentGuardResult(
                trace_id=resp_trace_id,
                decision=outcome,
                reason_codes=reason_codes,
                execution=exec_detail,
                risk=risk,
                approval_id=approval_id,
                execution_id=resp_execution_id,
            )

            # Raise typed exceptions for non-ALLOW outcomes
            if outcome == Decision.BLOCK:
                if "AGENT_QUARANTINED" in reason_codes or "BREAKER_TRIPPED" in reason_codes:
                    raise QuarantinedAgentError(
                        f"Agent {self.agent_id} is quarantined. All actions are blocked."
                    )
                raise BlockedActionError(
                    f"Action blocked by AgentGuard Gateway. Reason codes: {reason_codes}",
                    trace_id=resp_trace_id,
                    reason_codes=reason_codes,
                )
            if outcome == Decision.REQUIRE_APPROVAL:
                raise ApprovalRequiredError(
                    f"Action requires human approval. Check dashboard for approval ID.",
                    trace_id=resp_trace_id,
                    execution_id=resp_execution_id,
                    approval_id=approval_id or "",
                    reason_codes=reason_codes,
                    risk=risk,
                )

            return result

        except (AgentGuardError,):
            raise
        except (KeyError, TypeError, AttributeError) as exc:
            raise MalformedResponseError(f"Could not parse execute response: {exc}") from exc

    def _parse_evaluate_response(self, raw: dict[str, Any], trace_id: str) -> EvaluateResult:
        try:
            outcome_str = raw.get("decision", "BLOCK")
            try:
                outcome = Decision(outcome_str)
            except ValueError:
                outcome = Decision.BLOCK
            reasons_raw = raw.get("reasons", ())
            reason_codes = [r.get("code", "") if isinstance(r, dict) else str(r) for r in reasons_raw]
            risk = raw.get("risk", {}) or {}
            resp_trace_id = raw.get("trace_id", trace_id)
            return EvaluateResult(
                trace_id=resp_trace_id,
                decision=outcome,
                reason_codes=reason_codes,
                risk=risk,
                message=raw.get("message", ""),
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise MalformedResponseError(f"Could not parse evaluate response: {exc}") from exc

    # ------------------------------------------------------------------
    # Internal: HTTP transport
    # ------------------------------------------------------------------

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.gateway}{path}"
        if _httpx_available:
            return self._httpx_post(url, payload)
        return self._urllib_post(url, payload)

    def _get(self, path: str) -> Any:
        url = f"{self.gateway}{path}"
        if _httpx_available:
            return self._httpx_get(url)
        return self._urllib_get(url)

    def _httpx_post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        import httpx
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            raise TimeoutError(f"Gateway request timed out: {url}") from exc
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot connect to Gateway at {self.gateway}: {exc}") from exc
        except Exception as exc:
            raise ConnectionError(f"HTTP error: {exc}") from exc
        return self._handle_response(resp.status_code, resp.text, url)

    def _httpx_get(self, url: str) -> Any:
        import httpx
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
        except httpx.TimeoutException as exc:
            raise TimeoutError(f"Gateway request timed out: {url}") from exc
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot connect to Gateway at {self.gateway}: {exc}") from exc
        except Exception as exc:
            raise ConnectionError(f"HTTP error: {exc}") from exc
        return self._handle_response(resp.status_code, resp.text, url)

    def _urllib_post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        import json
        import urllib.request
        import urllib.error
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return self._handle_response(exc.code, body, url)
        except urllib.error.URLError as exc:
            if "timed out" in str(exc).lower():
                raise TimeoutError(f"Gateway request timed out: {url}") from exc
            raise ConnectionError(f"Cannot connect to Gateway at {self.gateway}: {exc}") from exc
        except Exception as exc:
            raise ConnectionError(f"HTTP error: {exc}") from exc

    def _urllib_get(self, url: str) -> Any:
        import json
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return self._handle_response(exc.code, body, url)
        except urllib.error.URLError as exc:
            if "timed out" in str(exc).lower():
                raise TimeoutError(f"Gateway request timed out: {url}") from exc
            raise ConnectionError(f"Cannot connect to Gateway at {self.gateway}: {exc}") from exc
        except Exception as exc:
            raise ConnectionError(f"HTTP error: {exc}") from exc

    @staticmethod
    def _handle_response(status_code: int, body: str, url: str) -> dict[str, Any]:
        import json
        if status_code == 401:
            raise AuthenticationError("Authentication failed. Check your agent token.")
        if status_code == 422:
            raise ValidationError(f"Request validation failed: {body[:500]}")
        if status_code >= 500:
            raise ExecutionError(f"Gateway server error ({status_code}): {body[:200]}")
        if status_code >= 400:
            raise AgentGuardError(f"Gateway error {status_code}: {body[:200]}")
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise MalformedResponseError(f"Gateway returned non-JSON response from {url}: {body[:100]}") from exc


def _resolve_approval_id(raw: dict[str, Any], execution_id: str) -> str | None:
    """Try to extract the approval_id from the gateway execute response."""
    # The gateway attaches approval info in the decision.reasons or nested structure
    decision_raw = raw.get("decision", {})
    if isinstance(decision_raw, dict):
        reasons = decision_raw.get("reasons", [])
        for r in reasons:
            if isinstance(r, dict) and r.get("code") == "REQUIRE_APPROVAL":
                return r.get("approval_id")
    return None
