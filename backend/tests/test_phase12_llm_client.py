"""Tests for LLM Client abstraction (Groq, Replay, caching, budgeting, redaction)."""

import pytest
from backend.services.llm_client import (
    LLMClient,
    LLMProviderError,
    LLMRequest,
    OllamaLLMProvider,
    ReplayLLMProvider,
    GroqLLMProvider,
)


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


def test_groq_failure_raises_explicit_error_without_fallback() -> None:
    groq = GroqLLMProvider(api_key="")
    with pytest.raises(Exception, match="GROQ_API_KEY is not configured"):
        groq.generate(LLMRequest(prompt="Hello"))


def test_groq_explicit_fallback_mode_tracking() -> None:
    fallback = ReplayLLMProvider({"safe": "Fallback plan output."})
    groq = GroqLLMProvider(api_key="", fallback_provider=fallback)

    req = LLMRequest(prompt="Execute safe operation", trace_id="trace-fb-1")
    res = groq.generate(req)
    assert res.mode == "fallback"
    assert "fallback" in res.provider
    assert res.content == "Fallback plan output."
    assert res.trace_id == "trace-fb-1"


def test_ollama_failure_and_fallback() -> None:
    # Test failing ollama provider (invalid URL)
    ollama = OllamaLLMProvider(base_url="http://127.0.0.1:9", fallback_provider=None)
    with pytest.raises(Exception, match="Ollama local provider failed"):
        ollama.generate(LLMRequest(prompt="Test prompt"))

    # Test ollama with explicit fallback
    fallback = ReplayLLMProvider({"test": "Ollama fallback result"})
    ollama_fb = OllamaLLMProvider(base_url="http://127.0.0.1:9", fallback_provider=fallback)
    res = ollama_fb.generate(LLMRequest(prompt="Test prompt"))
    assert res.mode == "fallback"
    assert res.content == "Ollama fallback result"


def test_groq_model_configuration_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    # 1. Fallback default
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    p_default = GroqLLMProvider(api_key="gsk_test")
    assert p_default.default_model == "llama-3.3-70b-versatile"

    # 2. GROQ_MODEL environment variable
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    p_env = GroqLLMProvider(api_key="gsk_test")
    assert p_env.default_model == "openai/gpt-oss-120b"

    # 3. Explicit constructor argument overrides environment variable
    p_explicit = GroqLLMProvider(api_key="gsk_test", default_model="custom/llama-3-custom")
    assert p_explicit.default_model == "custom/llama-3-custom"


def test_groq_rate_limit_retry_and_backoff_success(monkeypatch: pytest.MonkeyPatch) -> None:
    delays: list[float] = []
    calls: int = 0

    class MockGroqChat:
        def create(self, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                class RateLimitException(Exception):
                    status_code = 429
                raise RateLimitException("Rate limit reached: HTTP 429")

            class MockMessage:
                content = "Tool proposal after rate-limit backoff"
            class MockChoice:
                message = MockMessage()
            class MockUsage:
                total_tokens = 15
            class MockCompletion:
                choices = [MockChoice()]
                usage = MockUsage()
            return MockCompletion()

    class MockGroqClient:
        def __init__(self, api_key: str):
            self.chat = type("Chat", (), {"completions": MockGroqChat()})()

    import sys
    monkeypatch.setitem(sys.modules, "groq", type("groq_mod", (), {"Groq": MockGroqClient}))

    provider = GroqLLMProvider(
        api_key="gsk_valid_test_key",
        max_retries=3,
        initial_backoff_seconds=0.1,
        backoff_multiplier=2.0,
        sleep_fn=lambda d: delays.append(d),
    )

    req = LLMRequest(prompt="Propose action", trace_id="trace-rl-1")
    res = provider.generate(req)
    assert res.content == "Tool proposal after rate-limit backoff"
    assert res.mode == "live"
    assert calls == 2
    assert len(delays) == 1
    assert delays[0] == pytest.approx(0.1)


def test_groq_rate_limit_retry_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    delays: list[float] = []

    class MockGroqChat:
        def create(self, **kwargs):
            class RateLimitException(Exception):
                status_code = 429
            raise RateLimitException("Persistent 429 Too Many Requests")

    class MockGroqClient:
        def __init__(self, api_key: str):
            self.chat = type("Chat", (), {"completions": MockGroqChat()})()

    import sys
    monkeypatch.setitem(sys.modules, "groq", type("groq_mod", (), {"Groq": MockGroqClient}))

    provider = GroqLLMProvider(
        api_key="gsk_valid_test_key",
        max_retries=2,
        initial_backoff_seconds=0.05,
        backoff_multiplier=2.0,
        sleep_fn=lambda d: delays.append(d),
    )

    req = LLMRequest(prompt="Propose action", trace_id="trace-rl-ex")
    with pytest.raises(LLMProviderError, match="Groq live provider failed"):
        provider.generate(req)

    assert len(delays) == 2
    assert delays[0] == pytest.approx(0.05)
    assert delays[1] == pytest.approx(0.10)


def test_groq_non_429_does_not_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    delays: list[float] = []
    calls: int = 0

    class MockGroqChat:
        def create(self, **kwargs):
            nonlocal calls
            calls += 1
            class AuthException(Exception):
                status_code = 401
            raise AuthException("Invalid API key")

    class MockGroqClient:
        def __init__(self, api_key: str):
            self.chat = type("Chat", (), {"completions": MockGroqChat()})()

    import sys
    monkeypatch.setitem(sys.modules, "groq", type("groq_mod", (), {"Groq": MockGroqClient}))

    provider = GroqLLMProvider(
        api_key="gsk_invalid_test_key",
        max_retries=3,
        sleep_fn=lambda d: delays.append(d),
    )

    req = LLMRequest(prompt="Propose action", trace_id="trace-no-retry")
    with pytest.raises(LLMProviderError, match="Invalid API key"):
        provider.generate(req)

    assert calls == 1
    assert len(delays) == 0


def test_llm_budget_config_from_env_valid_and_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    from backend.services.llm_client import LLMBudgetConfig

    # Defaults
    for k in ("RUN_MAX_LLM_REQUESTS", "RUN_MAX_INPUT_TOKENS", "RUN_MAX_OUTPUT_TOKENS", "RUN_MAX_DURATION_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    b_def = LLMBudgetConfig.from_env()
    assert b_def.max_requests == 32
    assert b_def.max_input_tokens == 40_000
    assert b_def.max_output_tokens == 8_000
    assert b_def.max_duration_seconds == 180.0

    # Valid overrides
    monkeypatch.setenv("RUN_MAX_LLM_REQUESTS", "50")
    monkeypatch.setenv("RUN_MAX_INPUT_TOKENS", "60000")
    monkeypatch.setenv("RUN_MAX_OUTPUT_TOKENS", "12000")
    monkeypatch.setenv("RUN_MAX_DURATION_SECONDS", "300.5")
    b_custom = LLMBudgetConfig.from_env()
    assert b_custom.max_requests == 50
    assert b_custom.max_input_tokens == 60_000
    assert b_custom.max_output_tokens == 12_000
    assert b_custom.max_duration_seconds == 300.5

    # Invalid string values fallback safely
    monkeypatch.setenv("RUN_MAX_LLM_REQUESTS", "invalid_num")
    monkeypatch.setenv("RUN_MAX_INPUT_TOKENS", "-100")
    b_safe = LLMBudgetConfig.from_env()
    assert b_safe.max_requests == 32
    assert b_safe.max_input_tokens == 40_000


def test_llm_client_per_run_budget_exhaustion() -> None:
    from backend.services.llm_client import LLMBudgetConfig

    # 1. Request count exhaustion
    b_req = LLMBudgetConfig(max_requests=2, max_input_tokens=1000, max_output_tokens=1000, max_duration_seconds=60)
    client_req = LLMClient(provider=ReplayLLMProvider(), budget_config=b_req, enable_cache=False)
    client_req.generate(LLMRequest(prompt="One"))
    client_req.generate(LLMRequest(prompt="Two"))
    with pytest.raises(RuntimeError, match="Run request budget exhausted"):
        client_req.generate(LLMRequest(prompt="Three"))

    # 2. Input token exhaustion
    b_in = LLMBudgetConfig(max_requests=10, max_input_tokens=5, max_output_tokens=1000, max_duration_seconds=60)
    client_in = LLMClient(provider=ReplayLLMProvider(), budget_config=b_in, enable_cache=False)
    with pytest.raises(RuntimeError, match="Run input token budget exhausted"):
        client_in.generate(LLMRequest(prompt="Word1 Word2 Word3 Word4 Word5 Word6 Word7"))

    # 3. Output token exhaustion
    b_out = LLMBudgetConfig(max_requests=10, max_input_tokens=1000, max_output_tokens=5, max_duration_seconds=60)
    provider_verbose = ReplayLLMProvider({"long": "One two three four five six seven eight nine ten words."})
    client_out = LLMClient(provider=provider_verbose, budget_config=b_out, enable_cache=False)
    with pytest.raises(RuntimeError, match="Run output token budget exhausted"):
        client_out.generate(LLMRequest(prompt="long prompt"))


def test_trace_graph_llm_metadata_recording() -> None:
    from backend.services.trace_graph import TraceGraphService
    from backend.shared.contracts import Decision, DecisionOutcome

    tg = TraceGraphService()
    decision = Decision(
        decision=DecisionOutcome.ALLOW,
        agent_id="planner-01",
        tool_name="echo",
        task_id="task-1",
        trace_id="trace-meta-1",
        execution_id="exec-1",
    )

    # 1. Custom LLM metadata
    tg.record_step(
        trace_id="trace-meta-1",
        agent_id="planner-01",
        task_id="task-1",
        tool_name="echo",
        arguments={"value": "test"},
        decision=decision,
        execution_id="exec-1",
        llm_metadata={"llm_provider": "groq", "model": "openai/gpt-oss-120b", "mode": "live", "secret_key": "MUST_BE_STRIPPED"},
    )
    steps = tg.get_trace("trace-meta-1")
    assert len(steps) == 1
    assert steps[0]["llm_provider"] == "groq"
    assert steps[0]["model"] == "openai/gpt-oss-120b"
    assert steps[0]["mode"] == "live"
    assert "secret_key" not in steps[0]

    # 2. Replay default
    tg.record_step(
        trace_id="trace-meta-2",
        agent_id="planner-01",
        task_id="task-1",
        tool_name="echo",
        arguments={"value": "test"},
        decision=decision,
        execution_id="exec-2",
    )
    steps2 = tg.get_trace("trace-meta-2")
    assert len(steps2) == 1
    assert steps2[0]["llm_provider"] == "replay"
    assert steps2[0]["mode"] == "replay"
