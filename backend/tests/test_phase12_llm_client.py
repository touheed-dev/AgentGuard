"""Tests for LLM Client abstraction (Groq, Replay, caching, budgeting, redaction)."""

import pytest
from backend.services.llm_client import LLMClient, LLMRequest, ReplayLLMProvider, GroqLLMProvider


def test_llm_client_replay_mode() -> None:
    provider = ReplayLLMProvider()
    client = LLMClient(provider=provider)

    req = LLMRequest(
        prompt="Synthesize research for mission alpha",
        agent_id="planner-01",
        task_id="task-1",
        trace_id="trace-101",
    )
    res = client.generate(req)
    assert res.mode == "replay"
    assert res.provider == "replay"
    assert "Deterministic replay" in res.content
    assert res.trace_id == "trace-101"


def test_llm_client_caching() -> None:
    provider = ReplayLLMProvider({"plan": "Standard step 1-2-3 plan."})
    client = LLMClient(provider=provider, enable_cache=True)

    req = LLMRequest(prompt="Make a plan for analysis", trace_id="trace-cache-1")
    res1 = client.generate(req)
    assert res1.cached is False
    assert res1.content == "Standard step 1-2-3 plan."

    res2 = client.generate(req)
    assert res2.cached is True
    assert res2.provider == "cache"
    assert res2.content == "Standard step 1-2-3 plan."


def test_llm_client_redaction_before_egress() -> None:
    recorded_prompts: list[str] = []

    class MockProvider(ReplayLLMProvider):
        def generate(self, req: LLMRequest):
            recorded_prompts.append(req.prompt)
            return super().generate(req)

    mock = MockProvider()
    client = LLMClient(provider=mock)

    req = LLMRequest(
        prompt="Here is my token sk-abc1234567890abcdef1234 and honey asset AG-HONEY-SECRET-TOKEN",
        trace_id="trace-redact-1",
    )
    client.generate(req)

    assert len(recorded_prompts) == 1
    sent_prompt = recorded_prompts[0]
    assert "sk-" not in sent_prompt
    assert "AG-HONEY" not in sent_prompt
    assert "[REDACTED_SECRET]" in sent_prompt


def test_llm_client_budget_limit() -> None:
    provider = ReplayLLMProvider()
    client = LLMClient(provider=provider, max_daily_budget_tokens=5, enable_cache=False)

    req1 = LLMRequest(prompt="This is a test prompt one", trace_id="trace-budget-1")
    client.generate(req1)

    req2 = LLMRequest(prompt="This is a test prompt two", trace_id="trace-budget-2")
    with pytest.raises(RuntimeError, match="Daily token budget exhausted"):
        client.generate(req2)


def test_groq_fallback_when_no_api_key() -> None:
    groq = GroqLLMProvider(api_key="")
    with pytest.raises(RuntimeError, match="GROQ_API_KEY is not configured"):
        groq.generate(LLMRequest(prompt="Hello"))
