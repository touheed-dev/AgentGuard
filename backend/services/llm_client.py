"""LLM Client abstraction supporting Groq live provider, Ollama local provider, and deterministic Replay.

Conforms to PRD LLM Architecture:
- Provider abstraction (Groq, Ollama, Replay)
- Model registry
- Rate limiting / backoff support
- Request budgeting
- Response cache
- Strict API key isolation (keys never exposed to agents, tools, frontend, or sandbox)
- Pre-egress redaction
- Provider / model / mode tracing
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("agentguard.llm")


@dataclass(frozen=True)
class LLMRequest:
    prompt: str
    system_prompt: str = ""
    model: str = ""
    temperature: float = 0.0
    max_tokens: int = 1024
    agent_id: str = "unknown"
    task_id: str = "unknown"
    trace_id: str = "unknown"


@dataclass(frozen=True)
class LLMResponse:
    content: str
    provider: str
    model: str
    mode: str  # live | local | replay
    tokens_used: int
    cached: bool
    latency_ms: float
    trace_id: str


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        raise NotImplementedError


class LLMProviderError(RuntimeError):
    """Raised when an LLM provider fails to generate a completion."""
    pass


DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"


def _is_rate_limit_error(err: Exception) -> bool:
    if getattr(err, "status_code", None) == 429:
        return True
    err_type = err.__class__.__name__
    if "RateLimit" in err_type:
        return True
    err_msg = str(err).lower()
    return "429" in err_msg or "rate limit" in err_msg or "rate_limit" in err_msg


@dataclass(frozen=True)
class LLMBudgetConfig:
    max_requests: int = 32
    max_input_tokens: int = 40_000
    max_output_tokens: int = 8_000
    max_duration_seconds: float = 180.0

    @classmethod
    def from_env(cls) -> LLMBudgetConfig:
        def _parse_positive_int(key: str, default: int) -> int:
            raw = os.getenv(key)
            if raw is None or raw.strip() == "":
                return default
            try:
                val = int(raw.strip())
                if val <= 0:
                    logger.warning("Invalid non-positive value for %s: %r, using default %d", key, raw, default)
                    return default
                return val
            except ValueError:
                logger.warning("Invalid numeric value for %s: %r, using default %d", key, raw, default)
                return default

        def _parse_positive_float(key: str, default: float) -> float:
            raw = os.getenv(key)
            if raw is None or raw.strip() == "":
                return default
            try:
                val = float(raw.strip())
                if val <= 0.0:
                    logger.warning("Invalid non-positive value for %s: %r, using default %.1f", key, raw, default)
                    return default
                return val
            except ValueError:
                logger.warning("Invalid numeric value for %s: %r, using default %.1f", key, raw, default)
                return default

        return cls(
            max_requests=_parse_positive_int("RUN_MAX_LLM_REQUESTS", 32),
            max_input_tokens=_parse_positive_int("RUN_MAX_INPUT_TOKENS", 40_000),
            max_output_tokens=_parse_positive_int("RUN_MAX_OUTPUT_TOKENS", 8_000),
            max_duration_seconds=_parse_positive_float("RUN_MAX_DURATION_SECONDS", 180.0),
        )


class ReplayLLMProvider(LLMProvider):
    def __init__(self, predefined_responses: dict[str, str] | None = None) -> None:
        self._responses = predefined_responses or {
            "default": "Deterministic replay generation response from AgentGuard LLM subsystem."
        }

    def register_response(self, prompt_keyword: str, response: str) -> None:
        self._responses[prompt_keyword.lower()] = response

    def generate(self, request: LLMRequest) -> LLMResponse:
        start = time.perf_counter()
        selected = self._responses.get("default", "Deterministic mock completion")
        prompt_lower = request.prompt.lower()
        for k, v in self._responses.items():
            if k in prompt_lower:
                selected = v
                break

        latency_ms = (time.perf_counter() - start) * 1000.0
        return LLMResponse(
            content=selected,
            provider="replay",
            model=request.model,
            mode="replay",
            tokens_used=len(selected.split()),
            cached=False,
            latency_ms=latency_ms,
            trace_id=request.trace_id,
        )


class OllamaLLMProvider(LLMProvider):
    """Local Ollama provider for local airgapped execution."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        default_model: str = "llama3.2:latest",
        fallback_provider: LLMProvider | None = None,
    ) -> None:
        self.base_url = base_url
        self.default_model = default_model
        self.fallback_provider = fallback_provider

    def generate(self, request: LLMRequest) -> LLMResponse:
        start = time.perf_counter()
        model_name = request.model or self.default_model
        try:
            import urllib.request
            payload = json.dumps({
                "model": model_name,
                "prompt": f"{request.system_prompt}\n\n{request.prompt}" if request.system_prompt else request.prompt,
                "stream": False,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content = data.get("response", "")
                tokens = len(content.split())
        except Exception as err:
            if self.fallback_provider is not None:
                logger.warning("Ollama provider failed, using fallback: %s", err)
                res = self.fallback_provider.generate(request)
                return LLMResponse(
                    content=res.content,
                    provider=f"fallback:{res.provider}",
                    model=res.model,
                    mode="fallback",
                    tokens_used=res.tokens_used,
                    cached=res.cached,
                    latency_ms=(time.perf_counter() - start) * 1000.0,
                    trace_id=request.trace_id,
                )
            raise LLMProviderError(f"Ollama local provider failed: {err}") from err

        latency_ms = (time.perf_counter() - start) * 1000.0
        return LLMResponse(
            content=content,
            provider="ollama",
            model=model_name,
            mode="local",
            tokens_used=tokens,
            cached=False,
            latency_ms=latency_ms,
            trace_id=request.trace_id,
        )


class GroqLLMProvider(LLMProvider):
    def __init__(
        self,
        api_key: str | None = None,
        default_model: str | None = None,
        fallback_provider: LLMProvider | None = None,
        max_retries: int = 3,
        initial_backoff_seconds: float = 0.5,
        backoff_multiplier: float = 2.0,
        sleep_fn: Any = time.sleep,
    ) -> None:
        self._api_key = api_key if api_key is not None else os.getenv("GROQ_API_KEY", "")
        self.default_model = default_model or os.getenv("GROQ_MODEL") or DEFAULT_GROQ_MODEL
        self.fallback_provider = fallback_provider
        self.max_retries = max_retries
        self.initial_backoff_seconds = initial_backoff_seconds
        self.backoff_multiplier = backoff_multiplier
        self._sleep_fn = sleep_fn

    def generate(self, request: LLMRequest) -> LLMResponse:
        if not self._api_key:
            if self.fallback_provider is not None:
                res = self.fallback_provider.generate(request)
                return LLMResponse(
                    content=res.content,
                    provider=f"fallback:{res.provider}",
                    model=res.model,
                    mode="fallback",
                    tokens_used=res.tokens_used,
                    cached=res.cached,
                    latency_ms=res.latency_ms,
                    trace_id=request.trace_id,
                )
            raise LLMProviderError("GROQ_API_KEY is not configured.")

        start = time.perf_counter()
        target_model = request.model or self.default_model

        attempt = 0
        while True:
            try:
                from groq import Groq
                client = Groq(api_key=self._api_key)
                completion = client.chat.completions.create(
                    model=target_model,
                    messages=[
                        {"role": "system", "content": request.system_prompt or "You are a secure agent assistant."},
                        {"role": "user", "content": request.prompt},
                    ],
                    temperature=request.temperature,
                    max_tokens=request.max_tokens,
                )
                content = completion.choices[0].message.content or ""
                tokens = completion.usage.total_tokens if completion.usage else len(content.split())
                break
            except Exception as err:
                if _is_rate_limit_error(err) and attempt < self.max_retries:
                    attempt += 1
                    delay = self.initial_backoff_seconds * (self.backoff_multiplier ** (attempt - 1))
                    logger.warning("Groq rate limit encountered (attempt %d/%d), backing off for %.2fs: %s", attempt, self.max_retries, delay, err)
                    self._sleep_fn(delay)
                    continue

                if self.fallback_provider is not None:
                    logger.warning("Groq live provider failed, using fallback: %s", err)
                    res = self.fallback_provider.generate(request)
                    return LLMResponse(
                        content=res.content,
                        provider=f"fallback:{res.provider}",
                        model=res.model,
                        mode="fallback",
                        tokens_used=res.tokens_used,
                        cached=res.cached,
                        latency_ms=(time.perf_counter() - start) * 1000.0,
                        trace_id=request.trace_id,
                    )
                raise LLMProviderError(f"Groq live provider failed: {err}") from err

        latency_ms = (time.perf_counter() - start) * 1000.0
        return LLMResponse(
            content=content,
            provider="groq",
            model=target_model,
            mode="live",
            tokens_used=tokens,
            cached=False,
            latency_ms=latency_ms,
            trace_id=request.trace_id,
        )


class LLMClient:
    SENSITIVE_PATTERNS = [
        re.compile(r"sk-[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
        re.compile(r"gsk_[a-zA-Z0-9_\-]{20,}", re.IGNORECASE),
        re.compile(r"AG-HONEY-[A-Za-z0-9\-]+", re.IGNORECASE),
    ]

    def __init__(
        self,
        provider: LLMProvider | None = None,
        max_daily_budget_tokens: int | None = None,
        budget_config: LLMBudgetConfig | None = None,
        enable_cache: bool = True,
    ) -> None:
        self.provider = provider or (GroqLLMProvider() if os.getenv("GROQ_API_KEY") else ReplayLLMProvider())
        self.budget = budget_config or LLMBudgetConfig.from_env()
        self.max_daily_budget_tokens = max_daily_budget_tokens or 100_000
        self.enable_cache = enable_cache
        self._tokens_consumed = 0
        self._requests_count = 0
        self._input_tokens_consumed = 0
        self._output_tokens_consumed = 0
        self._start_time = time.time()
        self._cache: dict[str, str] = {}

    def _redact(self, text: str) -> str:
        redacted = text
        for pat in self.SENSITIVE_PATTERNS:
            redacted = pat.sub("[REDACTED_SECRET]", redacted)
        return redacted

    def _cache_key(self, req: LLMRequest) -> str:
        payload = f"{req.model}:{req.temperature}:{req.system_prompt}:{req.prompt}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def generate(self, request: LLMRequest) -> LLMResponse:
        elapsed = time.time() - self._start_time
        if elapsed > self.budget.max_duration_seconds:
            raise RuntimeError(f"Run duration budget exceeded ({elapsed:.1f}s > {self.budget.max_duration_seconds:.1f}s)")

        if self._requests_count >= self.budget.max_requests:
            raise RuntimeError(f"Run request budget exhausted ({self._requests_count}/{self.budget.max_requests})")

        approx_input_tokens = len(request.prompt.split()) + len(request.system_prompt.split())
        if self._input_tokens_consumed + approx_input_tokens > self.budget.max_input_tokens:
            raise RuntimeError(f"Run input token budget exhausted ({self._input_tokens_consumed + approx_input_tokens} > {self.budget.max_input_tokens})")

        if self._tokens_consumed >= self.max_daily_budget_tokens:
            raise RuntimeError(f"Daily token budget exhausted ({self._tokens_consumed}/{self.max_daily_budget_tokens})")

        sanitized_prompt = self._redact(request.prompt)
        sanitized_sys = self._redact(request.system_prompt)
        sanitized_req = LLMRequest(
            prompt=sanitized_prompt,
            system_prompt=sanitized_sys,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            agent_id=request.agent_id,
            task_id=request.task_id,
            trace_id=request.trace_id,
        )

        cache_key = self._cache_key(sanitized_req)
        if self.enable_cache and cache_key in self._cache:
            self._requests_count += 1
            self._input_tokens_consumed += approx_input_tokens
            return LLMResponse(
                content=self._cache[cache_key],
                provider="cache",
                model=sanitized_req.model,
                mode="cached",
                tokens_used=0,
                cached=True,
                latency_ms=0.1,
                trace_id=sanitized_req.trace_id,
            )

        response = self.provider.generate(sanitized_req)
        self._requests_count += 1
        self._input_tokens_consumed += approx_input_tokens
        self._output_tokens_consumed += response.tokens_used
        self._tokens_consumed += response.tokens_used

        if self._output_tokens_consumed > self.budget.max_output_tokens:
            raise RuntimeError(f"Run output token budget exhausted ({self._output_tokens_consumed} > {self.budget.max_output_tokens})")

        if self.enable_cache:
            self._cache[cache_key] = response.content

        return response
