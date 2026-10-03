from abc import ABC, abstractmethod
from datetime import datetime, timezone
import time
from typing import Any

from backend.core.threat_intel.models import (
    IndicatorType,
    ProviderHealth,
    ProviderResult,
    ProviderStatus,
    ReputationLevel,
)


class ThreatIntelProvider(ABC):
    """
    Abstract base class for threat intelligence providers.
    Provides standard status tracking, metrics, and normalized result generation.
    """

    def __init__(self, name: str, display_name: str, supported_types: list[IndicatorType], is_free_tier: bool = True):
        self.name = name
        self.display_name = display_name
        self.supported_types = supported_types
        self.is_free_tier = is_free_tier

        self.total_queries: int = 0
        self.successful_queries: int = 0
        self.failed_queries: int = 0
        self.total_latency_ms: float = 0.0
        self.last_queried_at: str | None = None
        self.last_error: str | None = None
        self.rate_limit_info: str | None = None

    @property
    @abstractmethod
    def has_api_key(self) -> bool:
        """Returns True if the required API key is configured in the environment."""
        pass

    @property
    def status(self) -> ProviderStatus:
        if not self.is_free_tier and not self.has_api_key:
            return ProviderStatus.NO_KEY
        if self.failed_queries > 0 and self.successful_queries == 0:
            return ProviderStatus.OFFLINE
        if self.failed_queries > 5 and self.failed_queries > (self.successful_queries / 2):
            return ProviderStatus.DEGRADED
        return ProviderStatus.ONLINE

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in self.supported_types

    def query(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        """
        Public wrapper around _lookup that handles timing, error handling,
        metric recording, and fallback.
        """
        if not self.supports(indicator_type):
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"message": f"Provider {self.name} does not support {indicator_type.value}"},
                latency_ms=0.0,
            )

        start_time = time.perf_counter()
        self.total_queries += 1
        now_iso = datetime.now(timezone.utc).isoformat()
        self.last_queried_at = now_iso

        try:
            result = self._lookup(indicator, indicator_type)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            result.latency_ms = round(elapsed_ms, 2)
            result.queried_at = now_iso
            self.total_latency_ms += elapsed_ms
            self.successful_queries += 1
            return result
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            self.total_latency_ms += elapsed_ms
            self.failed_queries += 1
            self.last_error = str(e)
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"error": str(e)},
                latency_ms=round(elapsed_ms, 2),
                error=str(e),
            )

    @abstractmethod
    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        """Provider specific implementation of indicator lookup."""
        pass

    def health_check(self) -> ProviderHealth:
        avg_lat = (
            round(self.total_latency_ms / self.total_queries, 2)
            if self.total_queries > 0
            else 0.0
        )
        return ProviderHealth(
            provider_name=self.name,
            display_name=self.display_name,
            status=self.status,
            has_api_key=self.has_api_key,
            total_queries=self.total_queries,
            successful_queries=self.successful_queries,
            failed_queries=self.failed_queries,
            avg_latency_ms=avg_lat,
            last_queried_at=self.last_queried_at,
            last_error=self.last_error,
            supported_types=self.supported_types,
            is_free_tier=self.is_free_tier,
            rate_limit_info=self.rate_limit_info,
        )

    def _build_result(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        reputation: ReputationLevel,
        risk_score: float,
        confidence: float,
        details: dict[str, Any],
        latency_ms: float = 0.0,
        source_url: str | None = None,
        raw_data: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> ProviderResult:
        return ProviderResult(
            provider_name=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=reputation,
            risk_score=round(risk_score, 2),
            confidence=round(confidence, 2),
            details=details,
            raw_data=raw_data,
            source_url=source_url,
            queried_at=datetime.now(timezone.utc).isoformat(),
            latency_ms=latency_ms,
            error=error,
        )
