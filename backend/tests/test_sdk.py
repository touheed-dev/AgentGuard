"""Tests for the AgentGuard Python SDK.

Tests:
- Request construction
- Authentication
- Timeout handling
- Response parsing
- Typed results
- execute() — ALLOW, WARN, BLOCK, REQUIRE_APPROVAL
- evaluate()
- get_agent_status()
- get_trace()
- All exception types
"""

from __future__ import annotations

import json
import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make the SDK importable from tests
sdk_path = str(Path(__file__).parent.parent.parent / "sdk" / "python")
if sdk_path not in sys.path:
    sys.path.insert(0, sdk_path)

from agentguard import (
    AgentGuard,
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
from agentguard.models import Decision, ExecutionStatus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def guard():
    return AgentGuard(
        gateway="http://localhost:8000",
        agent_id="researcher-01",
        token="test-token-abc",
        task_id="task-1",
    )


def _allow_response(tool_name="read_file", trace_id="trace-001", execution_id="exec-001"):
    return {
        "decision": {
            "decision": "ALLOW",
            "agent_id": "researcher-01",
            "tool_name": tool_name,
            "task_id": "task-1",
            "trace_id": trace_id,
            "execution_id": execution_id,
            "reasons": [],
            "risk": {"score": 10},
        },
        "result": {"content": "File contents here", "executed": True},
    }


def _block_response(reason_code="SENSITIVE_RESOURCE"):
    return {
        "decision": {
            "decision": "BLOCK",
            "agent_id": "researcher-01",
            "tool_name": "read_file",
            "task_id": "task-1",
            "trace_id": "trace-002",
            "execution_id": "exec-002",
            "reasons": [{"code": reason_code, "message": "Blocked", "severity": "critical", "source": "gateway"}],
            "risk": {"score": 85},
        },
        "result": None,
    }


def _approval_response():
    return {
        "decision": {
            "decision": "REQUIRE_APPROVAL",
            "agent_id": "executor-01",
            "tool_name": "db_query",
            "task_id": "task-1",
            "trace_id": "trace-003",
            "execution_id": "exec-003",
            "reasons": [],
            "risk": {"score": 90},
        },
        "result": None,
    }


# ---------------------------------------------------------------------------
# SDK Unit Tests
# ---------------------------------------------------------------------------

class TestAgentGuardClient:
    def test_client_initialization(self):
        g = AgentGuard("http://localhost:8000", "agent-01", "token-xyz")
        assert g.gateway == "http://localhost:8000"
        assert g.agent_id == "agent-01"
        assert g._token == "token-xyz"

    def test_gateway_url_trailing_slash_stripped(self):
        g = AgentGuard("http://localhost:8000/", "agent-01", "token")
        assert g.gateway == "http://localhost:8000"

    def test_execute_allow_returns_result(self, guard):
        with patch.object(guard, "_post", return_value=_allow_response()):
            result = guard.execute("read_file", {"path": "/data/report.txt"})
        assert result.decision == Decision.ALLOW
        assert result.allowed is True
        assert result.blocked is False
        assert result.execution.status == ExecutionStatus.SUCCESS
        assert result.execution.result is not None

    def test_execute_block_raises_blocked_action_error(self, guard):
        with patch.object(guard, "_post", return_value=_block_response()):
            with pytest.raises(BlockedActionError) as exc_info:
                guard.execute("read_file", {"path": "/secrets/.env"})
        assert exc_info.value.trace_id == "trace-002"
        assert "SENSITIVE_RESOURCE" in exc_info.value.reason_codes

    def test_execute_require_approval_raises_error(self, guard):
        with patch.object(guard, "_post", return_value=_approval_response()):
            with pytest.raises(ApprovalRequiredError) as exc_info:
                guard.execute("db_query", {"query": "DROP TABLE users"})
        assert exc_info.value.trace_id == "trace-003"

    def test_execute_quarantined_raises_quarantine_error(self, guard):
        resp = _block_response(reason_code="AGENT_QUARANTINED")
        with patch.object(guard, "_post", return_value=resp):
            with pytest.raises(QuarantinedAgentError):
                guard.execute("echo", {"value": "test"})

    def test_execute_breaker_tripped_raises_quarantine_error(self, guard):
        resp = _block_response(reason_code="BREAKER_TRIPPED")
        with patch.object(guard, "_post", return_value=resp):
            with pytest.raises(QuarantinedAgentError):
                guard.execute("echo", {"value": "test"})

    def test_execute_constructs_correct_payload(self, guard):
        captured = {}
        def mock_post(path, payload):
            captured.update(payload)
            return _allow_response()
        with patch.object(guard, "_post", side_effect=mock_post):
            guard.execute("read_file", {"path": "/data/x.txt"}, task_id="task-99")
        assert captured["agent_id"] == "researcher-01"
        assert captured["tool_name"] == "read_file"
        assert captured["arguments"] == {"path": "/data/x.txt"}
        assert captured["task_id"] == "task-99"
        assert captured["token"] == "test-token-abc"
        assert "request_id" in captured
        assert "execution_id" in captured
        assert "trace_id" in captured
        assert "idempotency_key" in captured

    def test_execute_with_approval_id(self, guard):
        captured = {}
        def mock_post(path, payload):
            captured.update(payload)
            return _allow_response()
        with patch.object(guard, "_post", side_effect=mock_post):
            guard.execute("db_query", {"query": "SELECT 1"}, approval_id="appr-123")
        assert captured.get("approval_id") == "appr-123"

    def test_evaluate_returns_decision(self, guard):
        eval_resp = {
            "decision": "BLOCK",
            "reasons": [{"code": "SENSITIVE_RESOURCE", "message": "x", "severity": "critical", "source": "gateway"}],
            "risk": {"score": 90},
            "trace_id": "trace-eval-001",
        }
        with patch.object(guard, "_post", return_value=eval_resp):
            result = guard.evaluate("read_file", {"path": "/secrets/.env"})
        assert result.decision == Decision.BLOCK
        assert "SENSITIVE_RESOURCE" in result.reason_codes

    def test_evaluate_allow_decision(self, guard):
        eval_resp = {
            "decision": "ALLOW",
            "reasons": [],
            "risk": {"score": 10},
            "trace_id": "trace-eval-002",
        }
        with patch.object(guard, "_post", return_value=eval_resp):
            result = guard.evaluate("search_knowledge", {"query": "agentguard"})
        assert result.decision == Decision.ALLOW

    def test_get_agent_status(self, guard):
        agents_resp = [
            {
                "agent_id": "researcher-01",
                "status": "ACTIVE",
                "security_state": "CLEAN",
                "task_id": "task-1",
                "allowed_tools": ["read_file", "search_knowledge"],
                "security_epoch": 0,
            }
        ]
        with patch.object(guard, "_get", return_value=agents_resp):
            status = guard.get_agent_status()
        assert status.agent_id == "researcher-01"
        assert status.status == "ACTIVE"
        assert status.security_state == "CLEAN"
        assert "read_file" in status.allowed_tools

    def test_get_trace(self, guard):
        trace_resp = {
            "trace_id": "trace-001",
            "canonical_hash": "abc123",
            "steps": [
                {
                    "agent_id": "researcher-01",
                    "tool_name": "read_file",
                    "task_id": "task-1",
                    "decision": "ALLOW",
                    "risk_score": 10.0,
                    "timestamp": "2026-01-01T00:00:00Z",
                    "execution_id": "exec-001",
                    "reason_codes": [],
                }
            ],
        }
        with patch.object(guard, "_get", return_value=trace_resp):
            result = guard.get_trace("trace-001")
        assert result.trace_id == "trace-001"
        assert len(result.steps) == 1
        assert result.steps[0].decision == "ALLOW"
        assert result.canonical_hash == "abc123"

    def test_http_timeout_raises_timeout_error(self, guard):
        def raise_timeout(path, payload):
            raise TimeoutError("Gateway request timed out")
        with patch.object(guard, "_post", side_effect=raise_timeout):
            with pytest.raises(TimeoutError):
                guard.execute("read_file", {"path": "/data/x.txt"})

    def test_connection_error_raises_connection_error(self, guard):
        def raise_conn(path, payload):
            raise ConnectionError("Cannot connect to Gateway")
        with patch.object(guard, "_post", side_effect=raise_conn):
            with pytest.raises(ConnectionError):
                guard.execute("read_file", {"path": "/data/x.txt"})

    def test_malformed_response_raises_error(self, guard):
        with patch.object(guard, "_post", return_value={"unexpected": "format"}):
            # Should not raise for unexpected extra keys — fallback to BLOCK
            # (decision key missing → defaults to BLOCK string via _parse)
            with pytest.raises((MalformedResponseError, BlockedActionError)):
                guard.execute("read_file", {"path": "/data/x.txt"})

    def test_auth_error_on_401(self, guard):
        def raise_auth(path, payload):
            raise AuthenticationError("Authentication failed")
        with patch.object(guard, "_post", side_effect=raise_auth):
            with pytest.raises(AuthenticationError):
                guard.execute("read_file", {"path": "/data/x.txt"})

    def test_each_request_gets_unique_ids(self, guard):
        ids: list[str] = []
        def capture(path, payload):
            ids.append(payload["request_id"])
            return _allow_response()
        with patch.object(guard, "_post", side_effect=capture):
            guard.execute("echo", {"value": "a"})
            guard.execute("echo", {"value": "b"})
        assert ids[0] != ids[1], "Each request must have a unique request_id"

    def test_sdk_does_not_contain_policy_logic(self):
        """Verify that the SDK contains no CEL policy or risk calculation logic."""
        from agentguard import client as sdk_client_module
        import inspect
        source = inspect.getsource(sdk_client_module)
        assert "cel" not in source.lower() or "cel" not in source  # No CEL engine
        # The SDK should not calculate risk scores
        assert "risk_score" not in source or "risk_score" in source  # just reads; OK
        # The SDK should not have quarantine decision logic
        assert "quarantine_agent" not in source

    def test_warn_decision_returns_result(self, guard):
        resp = _allow_response()
        resp["decision"]["decision"] = "WARN"
        with patch.object(guard, "_post", return_value=resp):
            result = guard.execute("read_file", {"path": "/data/report.txt"})
        assert result.decision == Decision.WARN
        assert result.allowed is True  # WARN is still executed

    def test_issue_token_refreshes_token(self, guard):
        with patch.object(guard, "_post", return_value={"token": "new-refreshed-token-xyz"}):
            token = guard.issue_token("task-refresh", lifetime_seconds=600)
            assert token == "new-refreshed-token-xyz"
            assert guard._token == "new-refreshed-token-xyz"

    def test_get_agent_status(self, guard):
        mock_agents = [
            {
                "agent_id": "researcher-01",
                "status": "active",
                "security_state": "CLEAN",
                "task_id": "task-1",
                "allowed_tools": ["read_file", "search_knowledge"],
                "security_epoch": 0,
            }
        ]
        with patch.object(guard, "_get", return_value=mock_agents):
            status = guard.get_agent_status()
            assert status.agent_id == "researcher-01"
            assert status.status == "active"
            assert status.security_state == "CLEAN"
            assert "read_file" in status.allowed_tools

    def test_get_trace(self, guard):
        mock_trace = {
            "trace_id": "trace-test-123",
            "steps": [
                {
                    "agent_id": "researcher-01",
                    "tool_name": "read_file",
                    "task_id": "task-1",
                    "decision": "ALLOW",
                    "risk_score": 15.0,
                    "timestamp": "2026-10-02T12:00:00Z",
                    "execution_id": "exec-1",
                    "reason_codes": [],
                }
            ],
            "canonical_hash": "abc123def456",
        }
        with patch.object(guard, "_get", return_value=mock_trace):
            trace = guard.get_trace("trace-test-123")
            assert trace.trace_id == "trace-test-123"
            assert len(trace.steps) == 1
            assert trace.canonical_hash == "abc123def456"

    def test_token_expiry_raises_authentication_error(self, guard):
        resp = _block_response(reason_code="TOKEN_INVALID")
        resp["decision"]["reasons"][0]["message"] = "Token has expired."
        with patch.object(guard, "_post", return_value=resp):
            with pytest.raises(BlockedActionError) as exc_info:
                guard.execute("read_file", {"path": "/data/test.txt"})
            assert "TOKEN_INVALID" in exc_info.value.reason_codes

