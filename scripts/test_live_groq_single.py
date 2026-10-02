import json
import os
import sys
import urllib.request
import uuid
from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

sys.path.insert(0, "W:/AgentGuard")

# Load local .env
load_dotenv("W:/AgentGuard/.env")

from backend.services.llm_client import GroqLLMProvider, LLMRequest
from backend.core.identity.service import IdentityService

def run_test():
    print("=== AGENTGUARD LIVE GROQ INTEGRATION VERIFICATION ===")
    
    # 1. Check Gateway health
    try:
        req = urllib.request.Request("http://localhost:8000/health")
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            health = json.loads(resp.read().decode("utf-8"))
            print(f"[1] Gateway Health: {health.get('status')} (mode={health.get('mode')})")
            if health.get("mode") != "live":
                print("FAIL: Gateway is not in live mode.")
                return False
    except Exception as e:
        print(f"FAIL: Gateway unreachable: {e}")
        return False

    # 2. Initialize Groq provider
    groq_api_key = os.getenv("GROQ_API_KEY", "")
    if not groq_api_key:
        print("FAIL: GROQ_API_KEY is not set in environment.")
        return False
    
    groq_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    print(f"[2] Provider Initialized: Groq (configured model={groq_model})")

    provider = GroqLLMProvider(default_model=groq_model)
    
    # 3. Generate unique execution identities per invocation
    unique_id = uuid.uuid4().hex[:12]
    trace_id = f"trace-live-{unique_id}"
    request_id = f"req-live-{unique_id}"
    execution_id = f"exec-live-{unique_id}"
    idempotency_key = f"idem-live-{unique_id}"
    
    # 4. Request structured tool action proposal from Groq
    llm_req = LLMRequest(
        prompt='Propose an action using the "echo" tool. Return ONLY a valid JSON object: {"tool": "echo", "arguments": {"value": "live-test-verified"}}',
        system_prompt="You are an autonomous AI agent integrated with AgentGuard security gateway. Respond strictly with raw JSON.",
        trace_id=trace_id,
    )
    
    print(f"[3] Sending single live request to Groq (trace_id={trace_id})...")
    try:
        llm_resp = provider.generate(llm_req)
        print(f"[4] Live Response Received from Groq:")
        print(f"    - Provider: {llm_resp.provider}")
        print(f"    - Model: {llm_resp.model}")
        print(f"    - Mode: {llm_resp.mode}")
        print(f"    - Tokens Used: {llm_resp.tokens_used}")
        print(f"    - Latency: {llm_resp.latency_ms:.1f}ms")
        print(f"    - Raw Proposal Content: {llm_resp.content.strip()[:100]}...")
    except Exception as e:
        print(f"FAIL: Groq live generation failed: {e}")
        return False

    # 5. Extract/formulate proposal tool arguments
    tool_name = "echo"
    tool_args = {"value": "live-test-verified"}
    try:
        parsed = json.loads(llm_resp.content.strip())
        if isinstance(parsed, dict) and "arguments" in parsed:
            tool_name = parsed.get("tool", "echo")
            tool_args = parsed.get("arguments", tool_args)
    except Exception:
        tool_args = {"value": llm_resp.content.strip()[:80] or "live-test-verified"}

    # 6. Route proposal through Gateway authorization boundary
    try:
        tok_req = urllib.request.Request(
            "http://localhost:8000/tokens/issue",
            data=json.dumps({
                "agent_id": "researcher-01",
                "task_id": "task-1",
                "capability_version": "cap-v1",
                "scope": [f"tool:{tool_name}", "tool:echo", "tool:get_demo_data"],
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(tok_req, timeout=5.0) as resp:
            token = json.loads(resp.read().decode("utf-8"))["token"]
    except Exception:
        identity = IdentityService()
        token = identity.issue_token("researcher-01", "task-1", "cap-v1", frozenset({f"tool:{tool_name}"}), 0)

    
    action_payload = {
        "request_id": request_id,
        "execution_id": execution_id,
        "agent_id": "researcher-01",
        "tool_name": tool_name,
        "arguments": tool_args,
        "task_id": "task-1",
        "trace_id": trace_id,
        "idempotency_key": idempotency_key,
        "token": token,
        "llm_metadata": {
            "llm_provider": llm_resp.provider,
            "model": llm_resp.model,
            "mode": llm_resp.mode,
        }
    }
    
    print(f"[5] Submitting proposal to Gateway for authorization evaluation (/actions/evaluate)...")
    print(f"    - request_id: {request_id}")
    print(f"    - execution_id: {execution_id}")
    try:
        eval_req = urllib.request.Request(
            "http://localhost:8000/actions/evaluate",
            data=json.dumps(action_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(eval_req, timeout=5.0) as resp:
            decision_data = json.loads(resp.read().decode("utf-8"))
            decision = decision_data.get("decision")
            reasons = decision_data.get("reasons", [])
            print(f"[6] Gateway Evaluation Decision: {decision} (reasons={[r.get('code') for r in reasons]})")
            
            if decision != "ALLOW":
                print(f"FAIL: Gateway did not allow proposal: {decision_data}")
                return False
    except Exception as e:
        print(f"FAIL: Gateway authorization failed: {e}")
        return False

    # 7. Execute proposal through Gateway execution boundary
    print("[7] Submitting proposal to Gateway for execution (/actions/execute)...")
    try:
        exec_req = urllib.request.Request(
            "http://localhost:8000/actions/execute",
            data=json.dumps(action_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(exec_req, timeout=5.0) as resp:
            exec_data = json.loads(resp.read().decode("utf-8"))
            exec_decision = exec_data.get("decision", {}).get("decision")
            print(f"    - Gateway Execution Decision: {exec_decision} (result={exec_data.get('result')})")
            if exec_decision != "ALLOW":
                print(f"FAIL: Gateway execution failed: {exec_data}")
                return False
    except Exception as e:
        print(f"FAIL: Gateway execution request failed: {e}")
        return False

    # 8. Check trace metadata and secret isolation
    print(f"[8] Inspecting trace record (/traces/{trace_id})...")
    try:
        trace_req = urllib.request.Request(f"http://localhost:8000/traces/{trace_id}")
        with urllib.request.urlopen(trace_req, timeout=5.0) as resp:
            trace_data = json.loads(resp.read().decode("utf-8"))
            steps = trace_data.get("steps", [])
            if not steps:
                print("FAIL: No steps found in trace.")
                return False
            step = steps[0]
            print(f"    - Recorded llm_provider: {step.get('llm_provider')}")
            print(f"    - Recorded model: {step.get('model')}")
            print(f"    - Recorded mode: {step.get('mode')}")
            
            # Secret hygiene assertion
            trace_str = json.dumps(trace_data)
            if groq_api_key in trace_str or "gsk_" in trace_str:
                print("FAIL: Secret leaked into trace!")
                return False
            print("[9] Secret Isolation Verified: No API keys present in trace.")
    except Exception as e:
        print(f"FAIL: Trace inspection failed: {e}")
        return False

    # 9. Regression assertion: Deliberate duplicate request MUST be rejected
    print("[10] Testing Replay Defense: Submitting deliberate duplicate request identity...")
    try:
        dup_req = urllib.request.Request(
            "http://localhost:8000/actions/evaluate",
            data=json.dumps(action_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(dup_req, timeout=5.0) as resp:
            dup_decision_data = json.loads(resp.read().decode("utf-8"))
            dup_decision = dup_decision_data.get("decision")
            dup_reasons = [r.get("code") for r in dup_decision_data.get("reasons", [])]
            print(f"    - Duplicate Decision: {dup_decision} (reasons={dup_reasons})")
            
            if dup_decision != "BLOCK" or ("REQUEST_REPLAYED" not in dup_reasons and "EXECUTION_DUPLICATE" not in dup_reasons):
                print(f"FAIL: Deliberate duplicate was not properly blocked with replay/duplicate reason: {dup_decision_data}")
                return False
            print("[11] Replay Protection Verified: Duplicate request successfully rejected with REQUEST_REPLAYED / EXECUTION_DUPLICATE.")
    except Exception as e:
        print(f"FAIL: Duplicate request assertion failed: {e}")
        return False

    print("\n==================================================")
    print("LIVE GROQ TEST RESULT: ALL CHECKS PASSED")
    print("==================================================")
    return True

if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)


