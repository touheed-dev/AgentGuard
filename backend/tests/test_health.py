from fastapi.testclient import TestClient

from backend.apps.gateway.main import app


def test_health_endpoint_reports_replay_mode() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "mode": "replay"}
