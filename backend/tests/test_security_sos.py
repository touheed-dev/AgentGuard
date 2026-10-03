import json
import pytest
from fastapi.testclient import TestClient

from backend.apps.gateway.main import app, gateway
from backend.core.incidents.service import IncidentService, IncidentState, SecuritySOSEvent
from backend.shared.contracts import EventType, ReasonCode


def test_incident_service_generates_sos_on_critical() -> None:
    incidents = IncidentService()
    
    # Non-critical incident: should NOT produce an SOS event
    inc_med = incidents.create(
        agent_id="agent-01",
        task_id="task-01",
        trace_id="trace-01",
        reason_code="TASK_INCONSISTENT",
        severity="medium",
    )
    assert len(incidents.get_sos_events()) == 0

    # Critical incident: MUST produce a SECURITY_SOS event
    inc_crit = incidents.create(
        agent_id="agent-01",
        task_id="task-01",
        trace_id="trace-02",
        reason_code=ReasonCode.HONEY_ASSET_TOUCHED.value,
        severity="critical",
        details={"matched_marker": "AG-HONEY-TEST"},
    )
    
    sos_events = incidents.get_sos_events()
    assert len(sos_events) == 1
    event = sos_events[0]
    assert event.event_type == "security.sos"
    assert event.incident_id == inc_crit.incident_id
    assert event.agent_id == "agent-01"
    assert event.reason_code == ReasonCode.HONEY_ASSET_TOUCHED.value
    assert event.severity == "critical"
    assert event.details.get("matched_marker") == "AG-HONEY-TEST"


def test_incident_service_subscribers_notified() -> None:
    incidents = IncidentService()
    received = []

    def subscriber(event: SecuritySOSEvent) -> None:
        received.append(event)

    incidents.add_sos_subscriber(subscriber)

    incidents.create("agent-x", "task-x", "trace-x", "BREAKER_TRIPPED", "critical")
    assert len(received) == 1
    assert received[0].reason_code == "BREAKER_TRIPPED"

    incidents.remove_sos_subscriber(subscriber)
    incidents.create("agent-y", "task-y", "trace-y", "HONEY_ASSET_TOUCHED", "critical")
    assert len(received) == 1  # Unsubscribed, no new deliveries


def test_gateway_security_sos_endpoints() -> None:
    client = TestClient(app)
    client.post("/demo/reset")

    # Initially empty
    res = client.get("/security/sos")
    assert res.status_code == 200
    assert res.json() == []

    # Trigger honeytoken breach (creates critical incident)
    act4_res = client.post("/demo/act4/honeytoken")
    assert act4_res.status_code == 200
    assert act4_res.json()["decision"] == "BLOCK"

    # Verify SOS event recorded and retrievable via GET /security/sos
    sos_res = client.get("/security/sos")
    assert sos_res.status_code == 200
    events = sos_res.json()
    assert len(events) >= 1
    sos_event = events[0]
    assert sos_event["event_type"] == "security.sos"
    assert sos_event["reason_code"] == ReasonCode.HONEY_ASSET_TOUCHED.value
    assert sos_event["severity"] == "critical"
    assert sos_event["agent_id"] == "executor-01"

    # Reset clears events
    reset_res = client.post("/demo/reset")
    assert reset_res.status_code == 200
    assert client.get("/security/sos").json() == []
