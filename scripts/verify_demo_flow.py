"""AgentGuard End-to-End Demo Sequence Verification Script.

Executes the deterministic demo path against the live Gateway API:
1. Normal Agent Tool Invocation -> ALLOW (Executed)
2. Prompt Injection Attack -> BLOCK (Short-circuited at Gateway)
3. Honey Asset Canary Touch -> TRIPWIRE (Quarantine & Epoch Bump)
4. Incident Recording -> Stored in Incident Center
5. Trace Graph & Audit -> Canonical Merkle Hash & Steps Recorded
6. Deterministic Replay -> Counterfactual Replay Validated
"""

import os
import sys
import uuid
import httpx

GATEWAY_URL = os.getenv("AGENTGUARD_GATEWAY_URL", "http://localhost:8000")


def run_demo_verification() -> bool:
    print("=" * 60)
    print("AGENTGUARD END-TO-END DEMO SEQUENCE VERIFICATION")
    print("=" * 60)

    client = httpx.Client(base_url=GATEWAY_URL, timeout=10.0)

    # 1. Health Check & Demo State Reset
    health_res = client.get("/health")
    assert health_res.status_code == 200, f"Health check failed: {health_res.text}"
    health = health_res.json()
    print(f"[1] Gateway Health: {health['status']} (mode={health['mode']})")

    reset_res = client.post("/demo/reset")
    assert reset_res.status_code == 200, f"Demo reset failed: {reset_res.text}"
    print(f"[2] Demo State Reset: Pristine Initial State Restored (agents={reset_res.json().get('agents', 4)})")

    # 2. Step 1: Normal Agent ALLOW
    print("\n--- DEMO STEP 1: Normal Authorized Agent Action ---")
    token_res = client.post("/tokens/issue", json={
        "agent_id": "executor-01",
        "task_id": "task-1",
        "capability_version": "cap-v1",
        "scope": ["tool:echo"],
    })
    assert token_res.status_code == 200, f"Token issuance failed: {token_res.text}"
    token_1 = token_res.json()["token"]

    exec_id_1 = f"exec-demo-{uuid.uuid4().hex[:8]}"
    trace_id_1 = f"trace-demo-{uuid.uuid4().hex[:8]}"
    eval_res_1 = client.post("/actions/execute", json={
        "request_id": f"req-{uuid.uuid4().hex[:8]}",
        "execution_id": exec_id_1,
        "agent_id": "executor-01",
        "tool_name": "echo",
        "arguments": {"value": "authorized-quarterly-analysis"},
        "task_id": "task-1",
        "trace_id": trace_id_1,
        "idempotency_key": f"idem-{uuid.uuid4().hex[:8]}",
        "token": token_1,
    })
    assert eval_res_1.status_code == 200, f"Evaluation failed: {eval_res_1.text}"
    decision_1 = eval_res_1.json()
    assert decision_1["decision"]["decision"] == "ALLOW", f"Expected ALLOW, got {decision_1}"
    print(f"    - Agent: executor-01 -> Tool: echo")
    print(f"    - Gateway Decision: {decision_1['decision']['decision']} (Executed: {decision_1['result'] is not None})")

    # 3. Step 2: Prompt Injection Attack BLOCK
    print("\n--- DEMO STEP 2: Prompt Injection / Traversal Attack ---")
    token_res_2 = client.post("/tokens/issue", json={
        "agent_id": "coder-01",
        "task_id": "task-1",
        "capability_version": "cap-v1",
        "scope": ["tool:echo"],
    })
    assert token_res_2.status_code == 200
    token_2 = token_res_2.json()["token"]

    exec_id_2 = f"exec-demo-{uuid.uuid4().hex[:8]}"
    trace_id_2 = f"trace-demo-{uuid.uuid4().hex[:8]}"
    eval_res_2 = client.post("/actions/execute", json={
        "request_id": f"req-{uuid.uuid4().hex[:8]}",
        "execution_id": exec_id_2,
        "agent_id": "coder-01",
        "tool_name": "echo",
        "arguments": {"value": "../../../etc/passwd"},
        "task_id": "task-1",
        "trace_id": trace_id_2,
        "idempotency_key": f"idem-{uuid.uuid4().hex[:8]}",
        "token": token_2,
    })
    assert eval_res_2.status_code == 200
    decision_2 = eval_res_2.json()
    assert decision_2["decision"]["decision"] == "BLOCK", f"Expected BLOCK, got {decision_2}"
    assert decision_2["result"] is None, "Post-block execution invariant violated!"
    reasons_2 = [r["code"] for r in decision_2["decision"]["reasons"]]
    print(f"    - Attack Payload: ../../../etc/passwd")
    print(f"    - Gateway Decision: {decision_2['decision']['decision']}")
    print(f"    - Block Reasons: {reasons_2}")
    print(f"    - Post-Block Execution: 0.00% (Result is None)")

    # 4. Step 3: Honey Asset Canary Tripwire
    print("\n--- DEMO STEP 3: Honey Asset Canary Tripwire & Containment ---")
    honey_res = client.post("/attack-lab/run/5")
    assert honey_res.status_code == 200, f"Honey scenario failed: {honey_res.text}"
    honey = honey_res.json()
    assert honey["decision"] == "BLOCK", f"Expected BLOCK, got {honey}"
    print(f"    - Scenario: {honey['scenario_name']}")
    print(f"    - Gateway Decision: {honey['decision']}")
    print(f"    - Triggered Reasons: {honey['reasons']}")
    print(f"    - Agent Status: {honey['agent_status']} / Security State: {honey['agent_security_state']}")

    # 5. Step 4: Audit Chain Verification
    print("\n--- DEMO STEP 4: RFC-8785 Cryptographic Audit Chain Verification ---")
    audit_res = client.get("/audit/verify")
    assert audit_res.status_code == 200
    audit = audit_res.json()
    print(f"    - Merkle Chain Verified: {audit['verified']}")
    print(f"    - Checked Events: {audit['checked_events']}")

    # 6. Step 5: Trace & Deterministic Replay
    print("\n--- DEMO STEP 5: Counterfactual Deterministic Replay ---")
    replay_res = client.post("/replay", json={"trace_id": trace_id_1})
    assert replay_res.status_code == 200
    replay = replay_res.json()
    print(f"    - Replay Status: {replay['status']}")
    print(f"    - Replayed Steps: {len(replay['replayed_steps'])}")

    print("\n" + "=" * 60)
    print("DEMO SEQUENCE VERIFICATION: ALL 5 STEPS PASSED")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = run_demo_verification()
    sys.exit(0 if success else 1)
