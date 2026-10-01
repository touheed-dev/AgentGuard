from backend.apps.gateway.runtime import create_runtime
from backend.services.trace_graph import TraceGraphService
from backend.shared.contracts import Decision, DecisionOutcome, Reason, ReasonCode


def test_trace_graph_step_recording_and_nodes() -> None:
    service = TraceGraphService()
    decision = Decision(
        decision=DecisionOutcome.BLOCK,
        agent_id="researcher-01",
        tool_name="read_secrets",
        task_id="task-1",
        trace_id="trace-tg-1",
        execution_id="exec-tg-1",
        reasons=(Reason(code=ReasonCode.HONEY_ASSET_TOUCHED, message="Honey asset touched", severity="critical", source="gateway"),),
    )

    service.record_step(
        trace_id="trace-tg-1",
        agent_id="researcher-01",
        task_id="task-1",
        tool_name="read_secrets",
        arguments={"path": "AG-HONEY"},
        decision=decision,
        execution_id="exec-tg-1",
        incident_id="inc-tg-1",
        risk_score=95.0,
    )

    trace = service.get_trace("trace-tg-1")
    assert len(trace) == 1
    assert trace[0]["tool_name"] == "read_secrets"
    assert trace[0]["risk_score"] == 95.0
    assert trace[0]["decision"] == "BLOCK"

    exported = service.export_graph_json()
    assert any(n["id"] == "agent:researcher-01" for n in exported["nodes"])
    assert any(n["id"] == "tool:read_secrets" for n in exported["nodes"])
    assert any(n["id"] == "incident:inc-tg-1" for n in exported["nodes"])


def test_trace_graph_communication_edges() -> None:
    service = TraceGraphService()
    service.record_communication("planner-01", "researcher-01", "task-1", allowed=True)
    service.record_communication("researcher-01", "coder-01", "task-1", allowed=False, reason="Denied path")

    exported = service.export_graph_json()
    assert len(exported["edges"]) == 2
    assert any(e["relationship"] == "communicates_with" and e["allowed"] is True for e in exported["edges"])
    assert any(e["relationship"] == "communicates_with" and e["allowed"] is False for e in exported["edges"])


def test_attack_graph_extraction_and_canonical_hash() -> None:
    service = TraceGraphService()
    decision_clean = Decision(decision=DecisionOutcome.ALLOW, agent_id="researcher-01", tool_name="echo", task_id="task-1", trace_id="trace-1", execution_id="exec-1")
    decision_attack = Decision(
        decision=DecisionOutcome.BLOCK,
        agent_id="coder-01",
        tool_name="execute_code",
        task_id="task-1",
        trace_id="trace-1",
        execution_id="exec-2",
        reasons=(Reason(code=ReasonCode.SENSITIVE_RESOURCE, message="Blocked sensitive file", severity="critical", source="gateway"),),
    )

    service.record_step("trace-1", "researcher-01", "task-1", "echo", {"value": "hi"}, decision_clean, "exec-1", risk_score=10.0)
    service.record_step("trace-1", "coder-01", "task-1", "execute_code", {"code": "cat /etc/shadow"}, decision_attack, "exec-2", incident_id="inc-att-1", risk_score=85.0)

    attack_graph = service.get_attack_graph_subgraph(min_risk=50.0)
    assert any(n["id"] == "incident:inc-att-1" for n in attack_graph["nodes"])
    assert any(n["id"] == "action:exec-2" for n in attack_graph["nodes"])

    # Canonical trace hash is deterministic
    h1 = service.compute_canonical_trace_hash("trace-1")
    h2 = service.compute_canonical_trace_hash("trace-1")
    assert h1 == h2
    assert len(h1) == 64
