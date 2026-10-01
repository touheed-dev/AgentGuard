import asyncio
from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from backend.apps.gateway.runtime import create_runtime
from backend.core.approval.service import ApprovalService, ApprovalStatus
from backend.core.breaker.service import BreakerService
from backend.core.communication.service import CommunicationService
from backend.core.identity.models import AgentStatus, SecurityState
from backend.core.incidents.service import IncidentService, IncidentState
from backend.infrastructure.database import create_engine
from backend.infrastructure.models import Base
from backend.infrastructure.repositories import ApprovalRepository, IncidentRepository, HoneyAssetRepository
from backend.services.executor import UnknownExecutionError
from backend.shared.contracts import DecisionOutcome, ReasonCode


def token_for(identity, agent_id="researcher-01", task_id="task-1"):
    return identity.issue_token(agent_id, task_id, "cap-v1", frozenset({"tool:echo", "tool:get_demo_data"}), 0)


def test_honey_asset_reference_quarantines_and_never_executes() -> None:
    gateway, identity, executor = create_runtime()

    decision = gateway.authorize("researcher-01", "read_secrets", {"path": "AG-HONEY-7F92-XK11"}, "task-1", "trace-honey", token_for(identity))
    agent = gateway.agents.get("researcher-01")

    assert decision.decision == DecisionOutcome.BLOCK
    assert decision.reasons[0].code == ReasonCode.HONEY_ASSET_TOUCHED
    assert agent is not None
    assert agent.security_state == SecurityState.QUARANTINED
    assert agent.status == AgentStatus.SUSPENDED
    assert agent.security_epoch == 1
    assert executor.execution_count == 0


def test_breaker_thresholds_medium_escalation_and_high_critical_suspension() -> None:
    breaker = BreakerService()
    # 3 medium in 60s -> tripped
    assert breaker.record("agent-m", "medium", 10.0).tripped is False
    assert breaker.record("agent-m", "medium", 20.0).tripped is False
    res3 = breaker.record("agent-m", "medium", 30.0)
    assert res3.tripped is True
    assert res3.suspended is False

    # Window expiry: after 60s, earlier medium events drop out
    assert breaker.record("agent-m2", "medium", 10.0).tripped is False
    assert breaker.record("agent-m2", "medium", 20.0).tripped is False
    # at t=75s, event at t=10s is expired (>60s ago)
    assert breaker.record("agent-m2", "medium", 75.0).tripped is False

    # 2 high events -> suspension
    assert breaker.record("agent-h", "high", 10.0).suspended is False
    assert breaker.record("agent-h", "high", 20.0).suspended is True

    # 1 critical event -> immediate suspension
    assert breaker.record("agent-c", "critical", 10.0).suspended is True


def test_breaker_enforcement_in_gateway() -> None:
    gateway, identity, _ = create_runtime()
    token = token_for(identity, "researcher-01")

    # Trip breaker by recording high events
    gateway.breaker.record("researcher-01", "critical", now=100.0)
    # Next request must be BLOCKED with BREAKER_TRIPPED
    decision = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-b", token, now=101.0)
    assert decision.decision == DecisionOutcome.BLOCK
    assert decision.reasons[0].code == ReasonCode.BREAKER_TRIPPED

    # Gateway execution must also be blocked
    dec, res = gateway.execute("researcher-01", "echo", {"value": "x"}, "task-1", "trace-b", token, now=101.0)
    assert dec.decision == DecisionOutcome.BLOCK
    assert dec.reasons[0].code == ReasonCode.BREAKER_TRIPPED
    assert res is None


def test_approval_lifecycle_and_enforcement() -> None:
    gateway, identity, executor = create_runtime()
    token = token_for(identity, "researcher-01")

    # Lower threshold or configure high risk to force REQUIRE_APPROVAL
    # Set risk on echo to trigger REQUIRE_APPROVAL: score >= 50
    # Let's mock risk or directly create an authorized REQUIRE_APPROVAL decision
    decision = gateway.authorize("researcher-01", "echo", {"value": "requires-approval"}, "task-1", "trace-app", token)
    # Modify decision outcome to REQUIRE_APPROVAL for test
    req_decision = decision.model_copy(update={"decision": DecisionOutcome.REQUIRE_APPROVAL})
    # Register fingerprint
    gateway._authorized_fingerprints[req_decision.execution_id] = gateway._decision_fingerprint(req_decision, {"value": "requires-approval"})
    
    # 1. Execution without approval -> CAPABILITY_DENIED (unapproved)
    app_id = gateway._pending_approvals.get(req_decision.execution_id)
    if not app_id:
        app = gateway.approvals.create({
            "agent_id": "researcher-01",
            "tool_name": "echo",
            "arguments": {"value": "requires-approval"},
            "task_id": "task-1",
            "trace_id": "trace-app",
            "execution_id": req_decision.execution_id,
        }, expires_at=200.0)
        app_id = app.approval_id
        gateway._pending_approvals[req_decision.execution_id] = app_id

    dec_unapproved, res = gateway.execute_authorized(
        req_decision, "researcher-01", "echo", {"value": "requires-approval"}, approval_id=app_id, now=100.0
    )
    assert dec_unapproved.decision == DecisionOutcome.BLOCK
    assert res is None

    # 2. Approve with modified arguments -> APPROVAL_STALE
    stale_app = gateway.approvals.approve(app_id, {
        "agent_id": "researcher-01",
        "tool_name": "echo",
        "arguments": {"value": "tampered"},
        "task_id": "task-1",
        "trace_id": "trace-app",
        "execution_id": req_decision.execution_id,
    }, now=100.0)
    assert stale_app.status == ApprovalStatus.STALE

    # 3. Create fresh approval, approve correctly -> execute succeeds
    fresh_app = gateway.approvals.create({
        "agent_id": "researcher-01",
        "tool_name": "echo",
        "arguments": {"value": "requires-approval"},
        "task_id": "task-1",
        "trace_id": "trace-app",
        "execution_id": req_decision.execution_id,
    }, expires_at=200.0)
    gateway.approvals.approve(fresh_app.approval_id, {
        "agent_id": "researcher-01",
        "tool_name": "echo",
        "arguments": {"value": "requires-approval"},
        "task_id": "task-1",
        "trace_id": "trace-app",
        "execution_id": req_decision.execution_id,
    }, now=110.0)

    dec_ok, res_ok = gateway.execute_authorized(
        req_decision, "researcher-01", "echo", {"value": "requires-approval"}, approval_id=fresh_app.approval_id, now=115.0
    )
    assert dec_ok.decision == DecisionOutcome.REQUIRE_APPROVAL
    assert res_ok == {"tool": "echo", "value": "requires-approval"}

    # 4. Expired approval -> APPROVAL_STALE
    exp_app = gateway.approvals.create({
        "agent_id": "researcher-01",
        "tool_name": "echo",
        "arguments": {"value": "requires-approval"},
        "task_id": "task-1",
        "trace_id": "trace-app",
        "execution_id": "exec-exp",
    }, expires_at=150.0)
    gateway.approvals.approve(exp_app.approval_id, {
        "agent_id": "researcher-01",
        "tool_name": "echo",
        "arguments": {"value": "requires-approval"},
        "task_id": "task-1",
        "trace_id": "trace-app",
        "execution_id": "exec-exp",
    }, now=140.0)
    # At time 160.0 (past expires_at 150.0):
    dec_exp = req_decision.model_copy(update={"execution_id": "exec-exp"})
    gateway._authorized_fingerprints["exec-exp"] = gateway._decision_fingerprint(dec_exp, {"value": "requires-approval"})
    dec_expired, _ = gateway.execute_authorized(
        dec_exp, "researcher-01", "echo", {"value": "requires-approval"}, approval_id=exp_app.approval_id, now=160.0
    )
    assert dec_expired.decision == DecisionOutcome.BLOCK
    assert dec_expired.reasons[0].code == ReasonCode.APPROVAL_STALE


def test_unknown_result_lifecycle_and_retry_prevention() -> None:
    gateway, identity, executor = create_runtime()
    token = token_for(identity, "researcher-01")

    executor.force_unknown = True
    dec, res = gateway.execute("researcher-01", "echo", {"value": "timeout"}, "task-1", "trace-unk", token, execution_id="exec-unk")
    assert dec.decision == DecisionOutcome.BLOCK
    assert dec.reasons[0].code == ReasonCode.RESULT_UNKNOWN
    assert res is None

    # Retry with same execution ID must be blocked as duplicate
    executor.force_unknown = False
    retry_dec, retry_res = gateway.execute_authorized(dec, "researcher-01", "echo", {"value": "timeout"})
    assert retry_dec.decision == DecisionOutcome.BLOCK
    assert retry_dec.reasons[0].code == ReasonCode.EXECUTION_DUPLICATE
    assert retry_res is None


def test_communication_authorization_boundary() -> None:
    gateway, identity, _ = create_runtime()

    # Allowed edge
    allowed = gateway.authorize_communication("planner-01", "researcher-01", task_id="task-1")
    assert allowed.allowed is True

    # Denied edge
    denied = gateway.authorize_communication("researcher-01", "coder-01", task_id="task-1")
    assert denied.allowed is False
    assert denied.code == ReasonCode.COMM_PATH_DENIED

    # Quarantined agent communication blocked
    researcher = gateway.agents.get("researcher-01")
    gateway.agents.replace(researcher.model_copy(update={"security_state": SecurityState.QUARANTINED}))
    quar = gateway.authorize_communication("researcher-01", "planner-01", task_id="task-1")
    assert quar.allowed is False
    assert quar.code == ReasonCode.AGENT_QUARANTINED


def test_incident_lifecycle_and_deduplication() -> None:
    incidents = IncidentService()
    inc1 = incidents.create("agent-1", "task-1", "trace-1", "HONEY_ASSET_TOUCHED", "critical", now=100.0)
    assert inc1.state == IncidentState.DETECTED

    # Deterministic deduplication
    inc1_dup = incidents.create("agent-1", "task-1", "trace-1", "HONEY_ASSET_TOUCHED", "critical", now=105.0)
    assert inc1.incident_id == inc1_dup.incident_id

    # Transitions
    inc_analyzed = incidents.transition(inc1.incident_id, IncidentState.ANALYZED)
    assert inc_analyzed.state == IncidentState.ANALYZED
    inc_contained = incidents.transition(inc1.incident_id, IncidentState.CONTAINED)
    assert inc_contained.state == IncidentState.CONTAINED
    inc_resolved = incidents.transition(inc1.incident_id, IncidentState.RESOLVED)
    assert inc_resolved.state == IncidentState.RESOLVED

    # Invalid transition from RESOLVED
    with pytest.raises(ValueError):
        incidents.transition(inc1.incident_id, IncidentState.DETECTED)


def test_request_id_not_poisoned_by_invalid_request() -> None:
    gateway, identity, _ = create_runtime()
    bad_token = "invalid-token"
    good_token = token_for(identity, "researcher-01")

    # 1. Invalid request with request_id="req-123" fails authorization
    first = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", bad_token, request_id="req-123")
    assert first.decision == DecisionOutcome.BLOCK
    assert first.reasons[0].code == ReasonCode.TOKEN_INVALID

    # 2. Subsequent valid request using same request_id="req-123" must succeed and NOT be treated as replayed
    second = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", good_token, request_id="req-123")
    assert second.decision == DecisionOutcome.ALLOW

    # 3. Third request replaying "req-123" must now be blocked as REQUEST_REPLAYED
    third = gateway.authorize("researcher-01", "echo", {"value": "x"}, "task-1", "trace-1", good_token, request_id="req-123")
    assert third.decision == DecisionOutcome.BLOCK
    assert third.reasons[0].code == ReasonCode.REQUEST_REPLAYED


def test_phase5_database_persistence(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'phase5.db'}")
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)

        approval_repo = ApprovalRepository()
        incident_repo = IncidentRepository()
        honey_repo = HoneyAssetRepository()

        now = datetime.now(timezone.utc)
        async with factory() as session:
            async with session.begin():
                app = await approval_repo.create(session, "app-1", "fp-1", "APPROVAL_PENDING", now, {"tool": "code"})
                inc = await incident_repo.create(session, "inc-1", "agent-1", "task-1", "trace-1", "HONEY_ASSET_TOUCHED", "critical", "DETECTED", "agent-1:task-1:trace-1:HONEY")
                honey = await honey_repo.create(session, "h-1", "token", "AG-HONEY-TEST")

            fetched_app = await approval_repo.get(session, "app-1")
            assert fetched_app is not None
            assert fetched_app.fingerprint == "fp-1"

            fetched_inc = await incident_repo.get_by_dedup_key(session, "agent-1:task-1:trace-1:HONEY")
            assert fetched_inc is not None
            assert fetched_inc.reason_code == "HONEY_ASSET_TOUCHED"

            honeys = await honey_repo.list(session)
            assert len(honeys) == 1
            assert honeys[0].marker == "AG-HONEY-TEST"

        await engine.dispose()

    asyncio.run(scenario())

def test_adversarial_security_containment() -> None:
    gateway, identity, executor = create_runtime()
    token = token_for(identity, 'researcher-01')

    # 1. Direct communication without allowlist
    res_direct = gateway.authorize_communication('researcher-01', 'unknown-recipient', task_id='task-1')
    assert res_direct.allowed is False

    # 2. Forged approval ID that does not exist in approval service
    dummy_decision = gateway.authorize('researcher-01', 'echo', {'value': 'secure'}, 'task-1', 'trace-sec', token)
    req_dec = dummy_decision.model_copy(update={'decision': DecisionOutcome.REQUIRE_APPROVAL})
    dec_forged, _ = gateway.execute_authorized(req_dec, 'researcher-01', 'echo', {'value': 'secure'}, approval_id='forged-approval-id')
    assert dec_forged.decision == DecisionOutcome.BLOCK
    assert dec_forged.reasons[0].code == ReasonCode.CAPABILITY_DENIED

    # 3. Quarantined agent cannot bypass via any tool
    researcher = gateway.agents.get('researcher-01')
    gateway.agents.replace(researcher.model_copy(update={'security_state': SecurityState.QUARANTINED}))
    dec_quar = gateway.authorize('researcher-01', 'echo', {'value': 'attempt'}, 'task-1', 'trace-sec', token)
    assert dec_quar.decision == DecisionOutcome.BLOCK
    assert dec_quar.reasons[0].code == ReasonCode.AGENT_QUARANTINED

    # 4. Breaker suspension blocks subsequent attempts immediately
    gateway.breaker.record('coder-01', 'critical')
    coder_token = token_for(identity, 'coder-01')
    dec_suspended = gateway.authorize('coder-01', 'echo', {'value': 'test'}, 'task-1', 'trace-sec', coder_token)
    assert dec_suspended.decision == DecisionOutcome.BLOCK
    assert dec_suspended.reasons[0].code == ReasonCode.BREAKER_TRIPPED
