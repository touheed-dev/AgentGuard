from fastapi.testclient import TestClient

from backend.apps.gateway.main import app, identity_service


def test_evaluate_and_execute_api_use_gateway_boundary() -> None:
    token = identity_service.issue_token(
        "researcher-01",
        "task-1",
        "cap-v1",
        frozenset({"tool:echo"}),
        0,
    )
    request = {
        "request_id": "request-api-1",
        "execution_id": "execution-api-1",
        "agent_id": "researcher-01",
        "tool_name": "echo",
        "arguments": {"value": "api-test"},
        "task_id": "task-1",
        "trace_id": "trace-api-1",
        "idempotency_key": "idempotency-api-1",
        "token": token,
    }

    with TestClient(app) as client:
        evaluated = client.post("/actions/evaluate", json=request)
        executed = client.post("/actions/execute", json=request)

    assert evaluated.status_code == 200
    assert evaluated.json()["decision"] == "ALLOW"
    assert executed.status_code == 200
    assert executed.json()["result"] == {"tool": "echo", "value": "api-test"}


def test_blocked_api_action_does_not_execute() -> None:
    request = {
        "request_id": "request-api-2",
        "execution_id": "execution-api-2",
        "agent_id": "researcher-01",
        "tool_name": "unknown-tool",
        "arguments": {},
        "task_id": "task-1",
        "trace_id": "trace-api-2",
        "idempotency_key": "idempotency-api-2",
        "token": identity_service.issue_token(
            "researcher-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 0
        ),
    }

    with TestClient(app) as client:
        response = client.post("/actions/execute", json=request)

    assert response.status_code == 200
    assert response.json()["decision"]["decision"] == "BLOCK"
    assert response.json()["result"] is None