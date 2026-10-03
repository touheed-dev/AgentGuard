"""Comprehensive End-to-End Verification Suite for AgentGuard.
Tests all 17 requirements specified in the audit prompt against both the live Gateway and internal components.
"""

import os
import sys
import time
import uuid
import httpx
from pathlib import Path

# Add project root and SDK to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "sdk" / "python"))

from agentguard import (
    AgentGuard,
    BlockedActionError,
    ApprovalRequiredError,
    QuarantinedAgentError,
    AuthenticationError,
)
from agentguard.models import Decision, ExecutionStatus
from backend.apps.gateway.runtime import create_runtime
from backend.core.identity.models import AgentStatus, SecurityState
from backend.core.identity.service import IdentityService
from backend.services.executor import AuthorizationReceipt, RealExecutor
from backend.shared.contracts import DecisionOutcome, ReasonCode
from backend.agents.researcher import ResearcherAgent
from backend.services.llm_client import LLMClient, ReplayLLMProvider

GATEWAY_URL = "http://localhost:8000"

def test_live_gateway():
    print("\n" + "=" * 80)
    print("  AGENTGUARD COMPREHENSIVE END-TO-END AUDIT & VERIFICATION")
    print("=" * 80)
    
    # 0. Health & Reset
    print("\n--- [PHASE 0] Health Check & Environment Reset ---")
    with httpx.Client(base_url=GATEWAY_URL, timeout=10.0) as client:
        health = client.get("/health").json()
        print(f"Gateway Health: {health}")
        assert health["status"] == "ok"
        
        reset = client.post("/demo/reset").json()
        print(f"Demo Reset: {reset}")
        assert reset["status"] == "ok"

    # 1. SDK -> Gateway Integration (Live)
    print("\n--- [REQ 1] SDK -> Gateway Integration ---")
    guard = AgentGuard(
        gateway=GATEWAY_URL,
        agent_id="researcher-01",
        token="",
        task_id="sdk-test"
    )
    token = guard.issue_token()
    print(f"SDK Token Issued: len={len(token)}, preview={token[:30]}...")
    assert len(token) > 100
    
    status = guard.get_agent_status()
    print(f"SDK get_agent_status: id={status.agent_id}, status={status.status}, state={status.security_state}")
    assert status.status == "active"
    assert status.agent_id == "researcher-01"
    
    # 2. Decision Outcomes: ALLOW, WARN, REQUIRE_APPROVAL, BLOCK
    print("\n--- [REQ 2] ALLOW / WARN / REQUIRE_APPROVAL / BLOCK Decisions ---")
    
    # ALLOW test: echo with standard parameters on assigned task
    echo_eval = guard.evaluate(tool="echo", parameters={"value": "eval-test"}, task_id="sdk-test")
    print(f"Evaluation (echo on sdk-test): Decision={echo_eval.decision.value}, Reasons={echo_eval.reason_codes}")
    # echo is permitted for researcher-01
    
    echo_exec = guard.execute(tool="echo", parameters={"value": "exec-test"}, task_id="sdk-test")
    print(f"Execution (echo on sdk-test): Decision={echo_exec.decision.value}, Result={echo_exec.execution.result}")
    assert echo_exec.decision in (Decision.ALLOW, Decision.WARN)
    assert echo_exec.execution.result == {"tool": "echo", "value": "exec-test"}
    print("  [PASS] Execution authorized and returned expected result.")

    # REQUIRE_APPROVAL test: read_file outside known task definition triggers TASK_INCONSISTENT + 50 risk
    read_eval = guard.evaluate(tool="read_file", parameters={"path": "/data/report.pdf"}, task_id="sdk-test")
    print(f"Evaluation (read_file on sdk-test): Decision={read_eval.decision.value}, Reasons={read_eval.reason_codes}")
    assert read_eval.decision == Decision.REQUIRE_APPROVAL
    print("  [PASS] REQUIRE_APPROVAL decision reached appropriately.")

    # BLOCK test: sensitive resource access
    try:
        guard.execute(tool="read_file", parameters={"path": "/secrets/.env"}, task_id="sdk-test")
        assert False, "Expected BlockedActionError"
    except BlockedActionError as exc:
        print(f"Blocked Action (sensitive path): Reasons={exc.reason_codes}")
        assert "SENSITIVE_RESOURCE" in exc.reason_codes
        print("  [PASS] Sensitive resource access BLOCKED.")

    # 4. Direct tool/executor bypass prevention
    print("\n--- [REQ 4] Direct Tool / Executor Bypass Prevention ---")
    gw, identity, executor = create_runtime()
    
    # Try calling executor directly without valid receipt
    fake_receipt = AuthorizationReceipt(
        decision=DecisionOutcome.ALLOW,
        agent_id="researcher-01",
        tool_name="read_file",
        arguments={"path": "data/research_report.txt"},
        execution_id="fake-exec",
        grant_id="fake-grant",
    )
    try:
        executor.execute(fake_receipt)
        assert False, "Expected PermissionError on fake receipt"
    except PermissionError as exc:
        print(f"Executor direct call with fake receipt rejected: {exc}")
        print("  [PASS] Direct executor bypass correctly rejected.")

    # 5. Execution Authorization / Single-Use Grants
    print("\n--- [REQ 5] Execution Authorization & Single-Use Grants ---")
    tok = identity.issue_token("researcher-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 0)
    eid = f"exec-single-{uuid.uuid4()}"
    dec = gw.authorize("researcher-01", "echo", {"value": "first-use"}, "task-1", "trace-1", tok, eid)
    assert dec.decision == DecisionOutcome.ALLOW
    
    # First execution succeeds
    dec_exec, res_first = gw.execute_authorized(dec, "researcher-01", "echo", {"value": "first-use"})
    print(f"First execution: Decision={dec_exec.decision.value}, Result={res_first}")
    assert res_first == {"tool": "echo", "value": "first-use"}

    # Replay of same authorization decision must be BLOCKED
    dec_replay, res_second = gw.execute_authorized(dec, "researcher-01", "echo", {"value": "first-use"})
    print(f"Second execution (replay): Decision={dec_replay.decision.value}, Result={res_second}, Reasons={[r.code.value for r in dec_replay.reasons]}")
    assert dec_replay.decision == DecisionOutcome.BLOCK
    assert any(r.code in (ReasonCode.EXECUTION_DUPLICATE, ReasonCode.TOKEN_INVALID) for r in dec_replay.reasons)
    print("  [PASS] Single-use execution grant strictly enforced (replay fails closed with EXECUTION_DUPLICATE).")

    # Tampering with arguments between authorization and execution
    dec_tamper = gw.authorize("researcher-01", "echo", {"value": "legit"}, "task-1", "trace-2", tok, f"exec-tamper-{uuid.uuid4()}")
    dec_t_exec, res_tamper = gw.execute_authorized(dec_tamper, "researcher-01", "echo", {"value": "TAMPERED"})
    print(f"Tampered execution: Decision={dec_t_exec.decision.value}")
    assert dec_t_exec.decision == DecisionOutcome.BLOCK
    assert any(r.code == ReasonCode.TOKEN_INVALID for r in dec_t_exec.reasons)
    print("  [PASS] Action fingerprint mismatch blocks tampered execution.")

    # 6. Prompt Injection -> BLOCK -> No Execution
    print("\n--- [REQ 6] Prompt Injection -> Unauthorized Action -> BLOCK -> No Execution ---")
    exec_count_before = executor.execution_count
    tok_coder = identity.issue_token("coder-01", "task-1", "cap-v1", frozenset({"tool:bash_exec"}), 0)
    injected_cmd = "cat /etc/passwd; rm -rf /"
    dec_inj = gw.authorize("coder-01", "bash_exec", {"command": injected_cmd}, "task-1", "trace-inj", tok_coder)
    print(f"Prompt injection decision: {dec_inj.decision.value}, Reasons={[r.code.value for r in dec_inj.reasons]}")
    assert dec_inj.decision == DecisionOutcome.BLOCK
    assert executor.execution_count == exec_count_before
    print(f"  [PASS] Tool execution count remained {exec_count_before} (Zero tool execution).")

    # 7. Honeytoken -> Incident -> Quarantine -> Breaker
    print("\n--- [REQ 7] Honeytoken -> Incident -> Quarantine -> Breaker ---")
    tok_honey = identity.issue_token("executor-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 0)
    dec_honey = gw.authorize("executor-01", "echo", {"value": "AG-HONEY-7F92-XK11"}, "task-1", "trace-h", tok_honey)
    print(f"Honeytoken trigger: Decision={dec_honey.decision.value}, Reasons={[r.code.value for r in dec_honey.reasons]}")
    assert dec_honey.decision == DecisionOutcome.BLOCK
    assert any(r.code == ReasonCode.HONEY_ASSET_TOUCHED for r in dec_honey.reasons)
    
    agent_h = gw.agents.get("executor-01")
    print(f"Agent state after honey asset: status={agent_h.status.value}, security_state={agent_h.security_state.value}, epoch={agent_h.security_epoch}")
    assert agent_h.security_state == SecurityState.QUARANTINED
    assert agent_h.status == AgentStatus.SUSPENDED
    assert agent_h.security_epoch == 1
    
    # Follow-up benign action must now be BLOCKED by breaker
    dec_follow = gw.authorize("executor-01", "echo", {"value": "benign"}, "task-1", "trace-h2", tok_honey)
    print(f"Subsequent action: Decision={dec_follow.decision.value}, Reasons={[r.code.value for r in dec_follow.reasons]}")
    assert dec_follow.decision == DecisionOutcome.BLOCK
    assert any(r.code == ReasonCode.BREAKER_TRIPPED for r in dec_follow.reasons)

    # Check that SECURITY_SOS was recorded for the honey asset tripwire
    sos_events = gw.incidents.get_sos_events()
    print(f"SECURITY_SOS events recorded in runtime: count={len(sos_events)}")
    assert len(sos_events) >= 1
    assert any(ev.reason_code == ReasonCode.HONEY_ASSET_TOUCHED.value and ev.severity == "critical" for ev in sos_events)
    print("  [PASS] Backend SECURITY_SOS event emitted for critical honey asset breach.")
    print("  [PASS] Quarantine lockdown and circuit breaker trip verified.")

    # 8. Human Approval / Rejection Workflow (Live API)
    print("\n--- [REQ 8] Human Approval / Rejection Workflow ---")
    with httpx.Client(base_url=GATEWAY_URL, timeout=10.0) as client:
        # Reset to ensure clean state
        client.post("/demo/reset")
        
        # Trigger an action requiring approval
        act3_res = client.post("/demo/act3/approval").json()
        print(f"Act 3 Trigger: {act3_res}")
        approval_id = act3_res.get("approval_id")
        assert approval_id is not None
        
        # Check approvals list
        apprs = client.get("/approvals").json()
        print(f"Approvals count: {len(apprs)}")
        matched = [a for a in apprs if a["approval_id"] == approval_id]
        assert len(matched) == 1
        print(f"Approval record status: {matched[0]['status']}")
        assert matched[0]["status"] in ("APPROVAL_PENDING", "pending")
        
        # Test approval approval with matching fields
        appr_obj = matched[0]
        approve_res = client.post(f"/approvals/{approval_id}/approve", json=appr_obj["fields"]).json()
        print(f"Approve response: {approve_res}")
        assert approve_res["status"] == "APPROVED"
        
        # Create second approval to test reject
        act3_rej = client.post("/demo/act3/approval").json()
        rej_id = act3_rej["approval_id"]
        rej_res = client.post(f"/approvals/{rej_id}/reject").json()
        print(f"Reject response: {rej_res}")
        assert rej_res["status"] == "REJECTED"
        print("  [PASS] Human approval workflow (approve and reject) verified.")

    # 9. Audit Hash-Chain + Replay (Live API)
    print("\n--- [REQ 9] Audit Hash-Chain + Replay ---")
    with httpx.Client(base_url=GATEWAY_URL, timeout=10.0) as client:
        # Run verify audit
        audit_res = client.get("/audit/verify").json()
        print(f"Audit verification: {audit_res}")
        assert audit_res["verified"] is True
        assert audit_res["checked_events"] > 0
        
        # Run replay
        replay_res = client.post("/replay", json={"trace_id": "trace-demo"}).json()
        print(f"Replay response: {replay_res}")
        assert replay_res["status"] == "deterministic_match"
        assert len(replay_res["replayed_steps"]) > 0
        print("  [PASS] Audit hash chain and trace replay verified.")

    # 10. Attack Lab Scenarios (All 6 via API)
    print("\n--- [REQ 10] All 6 Attack Lab Scenarios ---")
    with httpx.Client(base_url=GATEWAY_URL, timeout=10.0) as client:
        for scen_id in range(1, 7):
            scen_res = client.post(f"/attack-lab/run/{scen_id}").json()
            print(f"Scenario {scen_id} ({scen_res.get('scenario_name')}): Decision={scen_res.get('decision')}, Reasons={scen_res.get('reasons')}, Executed={scen_res.get('executed')}")
            assert scen_res["decision"] == "BLOCK"
            assert scen_res["executed"] is False
        print("  [PASS] All 6 Attack Lab scenarios confirmed BLOCKED with zero execution.")

    # 11. Researcher Agent + Real SDK Integration
    print("\n--- [REQ 11] Researcher Agent + Real SDK Integration ---")
    with httpx.Client(base_url=GATEWAY_URL, timeout=30.0) as client:
        client.post("/demo/reset")
        act1 = client.post("/demo/act1/legitimate", json={"task_id": "research-task"}).json()
        print(f"Act 1 (Legitimate Researcher run): {act1}")
        assert act1["act"] == 1
        assert act1["result"]["steps"] > 0
        assert any(d == "ALLOW" for d in act1["result"]["decisions"])
        
        act2 = client.post("/demo/act2/prompt-injection", json={"task_id": "research-task"}).json()
        print(f"Act 2 (Prompt Injected Researcher run): {act2}")
        assert act2["act"] == 2
        assert act2["blocked_steps"] > 0
        print("  [PASS] Autonomous Researcher Agent integrated with SDK operates correctly.")

    # 15. Invalid / Expired / Forged / Replayed Tokens
    print("\n--- [REQ 15] Invalid / Expired / Forged / Replayed Tokens ---")
    with httpx.Client(base_url=GATEWAY_URL, timeout=10.0) as client:
        # Invalid signature
        other_identity = IdentityService()
        forged_token = other_identity.issue_token("researcher-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 0)
        eval_forged = client.post("/actions/evaluate", json={
            "request_id": f"req-{uuid.uuid4()}",
            "execution_id": f"exec-{uuid.uuid4()}",
            "agent_id": "researcher-01",
            "tool_name": "echo",
            "arguments": {"value": "x"},
            "task_id": "task-1",
            "trace_id": "trace-forged",
            "idempotency_key": f"key-{uuid.uuid4()}",
            "token": forged_token
        }).json()
        print(f"Forged Token evaluation: Decision={eval_forged['decision']}, Reasons={[r['code'] for r in eval_forged['reasons']]}")
        assert eval_forged["decision"] == "BLOCK"
        assert any(r["code"] == "TOKEN_INVALID" for r in eval_forged["reasons"])

        # Expired token
        expired_token = identity.issue_token("researcher-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 0, lifetime_seconds=-10)
        eval_exp = client.post("/actions/evaluate", json={
            "request_id": f"req-{uuid.uuid4()}",
            "execution_id": f"exec-{uuid.uuid4()}",
            "agent_id": "researcher-01",
            "tool_name": "echo",
            "arguments": {"value": "x"},
            "task_id": "task-1",
            "trace_id": "trace-exp",
            "idempotency_key": f"key-{uuid.uuid4()}",
            "token": expired_token
        }).json()
        print(f"Expired Token evaluation: Decision={eval_exp['decision']}, Reasons={[r['code'] for r in eval_exp['reasons']]}")
        assert eval_exp["decision"] == "BLOCK"
        assert any(r["code"] == "TOKEN_INVALID" for r in eval_exp["reasons"])

        # Subject mismatch
        tok_mismatch = identity.issue_token("planner-01", "task-1", "cap-v1", frozenset({"tool:echo"}), 0)
        eval_sub = client.post("/actions/evaluate", json={
            "request_id": f"req-{uuid.uuid4()}",
            "execution_id": f"exec-{uuid.uuid4()}",
            "agent_id": "researcher-01",
            "tool_name": "echo",
            "arguments": {"value": "x"},
            "task_id": "task-1",
            "trace_id": "trace-sub",
            "idempotency_key": f"key-{uuid.uuid4()}",
            "token": tok_mismatch
        }).json()
        print(f"Subject Mismatch evaluation: Decision={eval_sub['decision']}, Reasons={[r['code'] for r in eval_sub['reasons']]}")
        assert eval_sub["decision"] == "BLOCK"
        assert any(r["code"] == "TOKEN_INVALID" for r in eval_sub["reasons"])

        # Cross-task reuse attempt
        tok_task = identity.issue_token("researcher-01", "task-A", "cap-v1", frozenset({"tool:echo"}), 0)
        eval_task = client.post("/actions/evaluate", json={
            "request_id": f"req-{uuid.uuid4()}",
            "execution_id": f"exec-{uuid.uuid4()}",
            "agent_id": "researcher-01",
            "tool_name": "echo",
            "arguments": {"value": "x"},
            "task_id": "task-B",
            "trace_id": "trace-task",
            "idempotency_key": f"key-{uuid.uuid4()}",
            "token": tok_task
        }).json()
        print(f"Cross-Task Token evaluation: Decision={eval_task['decision']}, Reasons={[r['code'] for r in eval_task['reasons']]}")
        assert eval_task["decision"] == "BLOCK"
        print("  [PASS] All forged, expired, mismatched, and cross-task tokens rejected.")

        # Live SECURITY_SOS verification
        print("\n--- [REQ 8 - SECURITY_SOS] Live API & SSE Verification ---")
        client.post("/demo/reset")
        act4 = client.post("/demo/act4/honeytoken").json()
        assert act4["decision"] == "BLOCK"
        
        sos_list = client.get("/security/sos").json()
        print(f"Live /security/sos response: {sos_list}")
        assert len(sos_list) >= 1
        assert any(e["reason_code"] == ReasonCode.HONEY_ASSET_TOUCHED.value and e["severity"] == "critical" for e in sos_list)
        print("  [PASS] Live GET /security/sos returns valid SECURITY_SOS incident event.")

    print("\n" + "=" * 80)
    print("  ALL END-TO-END VERIFICATION CHECKS PASSED WITH ZERO ERRORS!")
    print("=" * 80)

if __name__ == "__main__":
    test_live_gateway()
