"""Tests for the Demo Environment and Agent Workspace endpoints."""
import pytest
from fastapi.testclient import TestClient
from backend.apps.gateway.main import app


@pytest.fixture(autouse=True)
def reset_gateway_state():
    with TestClient(app) as client:
        client.post("/demo/reset")
        yield
        client.post("/demo/reset")


def test_get_demo_environment() -> None:
    with TestClient(app) as client:
        resp = client.get("/demo/environment")
        assert resp.status_code == 200
        data = resp.json()
        assert "agent" in data
        assert data["agent"]["agent_id"] == "researcher-01"
        assert len(data["resources"]) >= 5
        
        # Verify resources classification
        res_paths = {r["path"]: r["classification"] for r in data["resources"]}
        assert res_paths.get("data/demo/public/research_report.txt") == "PUBLIC"
        assert res_paths.get("data/demo/untrusted/poisoned_document.txt") == "UNTRUSTED"
        assert res_paths.get("data/demo/restricted/.env") == "RESTRICTED"
        assert res_paths.get("data/demo/honey/AG-HONEY-7F92-XK11") == "HONEY_ASSET"
        
        # Verify DB tables
        assert len(data["database_tables"]) >= 3
        table_names = [t["table_name"] for t in data["database_tables"]]
        assert "customers" in table_names
        assert "transactions" in table_names
        assert "research_records" in table_names
        
        # Verify scenarios list
        assert len(data["scenarios"]) == 4


def test_demo_scenario_legitimate_research() -> None:
    with TestClient(app) as client:
        resp = client.post("/demo/scenarios/run", json={"scenario_id": "legitimate_research"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "legitimate_research"
        assert data["decision"] in ("ALLOW", "WARN")
        assert data["execution_status"] == "SUCCESS"
        assert data["executions_count"] >= 1
        assert data["output_preview"] is not None


def test_demo_scenario_prompt_injection_blocked_zero_execution() -> None:
    with TestClient(app) as client:
        resp = client.post("/demo/scenarios/run", json={"scenario_id": "prompt_injection"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "prompt_injection"
        assert data["decision"] == "BLOCK"
        assert "SENSITIVE_RESOURCE" in data["reasons"] or "POLICY_VIOLATION" in data["reasons"]
        assert data["execution_status"] == "NOT_EXECUTED"
        assert data["executions_count"] == 0
        assert data["output_preview"] is None


def test_demo_scenario_db_approval_flow() -> None:
    with TestClient(app) as client:
        resp = client.post("/demo/scenarios/run", json={"scenario_id": "db_approval"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "db_approval"
        assert data["decision"] == "REQUIRE_APPROVAL"
        assert data["execution_status"] == "PENDING_APPROVAL"
        assert data["approval_id"] is not None


def test_demo_scenario_honeytoken_tripwire_and_quarantine() -> None:
    with TestClient(app) as client:
        resp = client.post("/demo/scenarios/run", json={"scenario_id": "honeytoken_tripwire"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "honeytoken_tripwire"
        assert data["decision"] == "BLOCK"
        assert "HONEY_ASSET_TOUCHED" in data["reasons"]
        assert data["execution_status"] == "NOT_EXECUTED (QUARANTINED)"
        assert data["executions_count"] == 0
        assert data["agent_quarantined"] is True
