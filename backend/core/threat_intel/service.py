from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import os
from threading import RLock
import time
from typing import Any

from backend.core.threat_intel.extractors import ExtractedIndicator, IndicatorExtractor
from backend.core.threat_intel.models import (
    EnrichedIndicator,
    IndicatorType,
    ProviderHealth,
    ProviderResult,
    ProviderStatus,
    ReputationLevel,
)
from backend.core.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from backend.core.threat_intel.providers.base import ThreatIntelProvider
from backend.core.threat_intel.providers.cisa_kev import CISAKEVProvider
from backend.core.threat_intel.providers.greynoise import GreyNoiseProvider
from backend.core.threat_intel.providers.otx import OTXProvider
from backend.core.threat_intel.providers.shodan import ShodanProvider
from backend.core.threat_intel.providers.urlhaus import URLhausProvider
from backend.core.threat_intel.providers.virustotal import VirusTotalProvider


class CacheEntry:
    def __init__(self, data: EnrichedIndicator, expires_at: float):
        self.data = data
        self.expires_at = expires_at


class ThreatIntelService:
    """
    Threat Intelligence Orchestration Service.
    Aggregates multi-provider threat signals, provides high-performance TTL caching,
    concurrent querying, and indicator correlation for the pre-execution gateway.
    """

    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
        cache_ttl_seconds: float = 1800.0,
        max_workers: int = 6,
        timeout_seconds: float = 2.0,
    ):
        self._providers: dict[str, ThreatIntelProvider] = {}
        if providers:
            for p in providers:
                self._providers[p.name] = p
        else:
            # Default provider suite
            default_list = [
                AbuseIPDBProvider(),
                URLhausProvider(),
                CISAKEVProvider(),
                OTXProvider(),
                VirusTotalProvider(),
                ShodanProvider(),
                GreyNoiseProvider(),
            ]
            for p in default_list:
                self._providers[p.name] = p

        self._cache_ttl = cache_ttl_seconds
        self._timeout = timeout_seconds
        self._cache: dict[tuple[str, IndicatorType], CacheEntry] = {}
        self._cache_lock = RLock()
        self._thread_pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="threat-intel")

        # Live Metrics
        self.cache_hits: int = 0
        self.cache_misses: int = 0
        self.total_indicators_enriched: int = 0
        self.threats_blocked_count: int = 0
        self._recent_indicators: list[dict[str, Any]] = []
        self._max_recent: int = 150

    def get_provider(self, name: str) -> ThreatIntelProvider | None:
        return self._providers.get(name)

    def get_all_providers(self) -> list[ThreatIntelProvider]:
        return list(self._providers.values())

    def get_providers_health(self) -> list[ProviderHealth]:
        return [p.health_check() for p in self._providers.values()]

    def enrich_action(self, tool_name: str, arguments: dict[str, Any]) -> list[EnrichedIndicator]:
        """
        Extracts and enriches all indicators found within a tool execution request.
        """
        extracted = IndicatorExtractor.extract_from_arguments(tool_name, arguments)
        if not extracted:
            return []

        results: list[EnrichedIndicator] = []
        for item in extracted:
            enriched = self.enrich_indicator(
                indicator=item.value,
                indicator_type=item.indicator_type,
                source_context=item.source_context,
            )
            results.append(enriched)

        return results

    def enrich_indicator(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        source_context: str | None = None,
        force_refresh: bool = False,
    ) -> EnrichedIndicator:
        """
        Enriches a single indicator across all capable providers with TTL cache check.
        """
        cache_key = (indicator.strip().lower(), indicator_type)
        now = time.time()

        if not force_refresh:
            with self._cache_lock:
                entry = self._cache.get(cache_key)
                if entry and entry.expires_at > now:
                    self.cache_hits += 1
                    # Return copy marked as cached
                    cached_data = entry.data.model_copy(update={"cached": True})
                    self._record_recent(cached_data, source_context)
                    return cached_data

        with self._cache_lock:
            self.cache_misses += 1
            self.total_indicators_enriched += 1

        # Query all providers supporting this indicator type
        eligible_providers = [p for p in self._providers.values() if p.supports(indicator_type)]
        provider_results: list[ProviderResult] = []

        if len(eligible_providers) == 1:
            try:
                res = eligible_providers[0].query(indicator, indicator_type)
                provider_results.append(res)
            except Exception as e:
                provider_results.append(
                    ProviderResult(
                        provider_name=eligible_providers[0].name,
                        indicator=indicator,
                        indicator_type=indicator_type,
                        reputation=ReputationLevel.UNKNOWN,
                        risk_score=0.0,
                        confidence=0.0,
                        details={"error": str(e)},
                        queried_at=datetime.now(timezone.utc).isoformat(),
                        error=str(e),
                    )
                )
        elif eligible_providers:
            futures = {
                self._thread_pool.submit(p.query, indicator, indicator_type): p
                for p in eligible_providers
            }
            completed_futures = set()
            try:
                for future in as_completed(futures, timeout=self._timeout):
                    completed_futures.add(future)
                    try:
                        res = future.result()
                        provider_results.append(res)
                    except Exception as e:
                        prov = futures[future]
                        provider_results.append(
                            ProviderResult(
                                provider_name=prov.name,
                                indicator=indicator,
                                indicator_type=indicator_type,
                                reputation=ReputationLevel.UNKNOWN,
                                risk_score=0.0,
                                confidence=0.0,
                                details={"error": str(e)},
                                queried_at=datetime.now(timezone.utc).isoformat(),
                                error=str(e),
                            )
                        )
            except TimeoutError:
                for fut, prov in futures.items():
                    if fut not in completed_futures:
                        provider_results.append(
                            ProviderResult(
                                provider_name=prov.name,
                                indicator=indicator,
                                indicator_type=indicator_type,
                                reputation=ReputationLevel.UNKNOWN,
                                risk_score=0.0,
                                confidence=0.0,
                                details={"error": "Query timed out"},
                                queried_at=datetime.now(timezone.utc).isoformat(),
                                error="Query timed out",
                            )
                        )

        # Correlate and synthesize overall verdict
        enriched = self._correlate_results(indicator, indicator_type, provider_results, source_context)

        # Store in cache
        with self._cache_lock:
            self._cache[cache_key] = CacheEntry(data=enriched, expires_at=now + self._cache_ttl)

        self._record_recent(enriched, source_context)
        return enriched

    def _correlate_results(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        provider_results: list[ProviderResult],
        source_context: str | None,
    ) -> EnrichedIndicator:
        if not provider_results:
            return EnrichedIndicator(
                indicator=indicator,
                indicator_type=indicator_type,
                overall_reputation=ReputationLevel.UNKNOWN,
                overall_risk_score=0.0,
                max_confidence=0.0,
                provider_results=[],
                summary="No threat intelligence providers available for indicator type.",
                extracted_from=source_context,
            )

        max_risk: float = 0.0
        max_conf: float = 0.0
        primary_provider: str | None = None
        has_malicious = False
        has_suspicious = False
        tags: set[str] = set()

        for pr in provider_results:
            if pr.risk_score > max_risk:
                max_risk = pr.risk_score
                primary_provider = pr.provider_name
            if pr.confidence > max_conf:
                max_conf = pr.confidence
            if pr.reputation == ReputationLevel.MALICIOUS:
                has_malicious = True
                tags.add(f"{pr.provider_name}:malicious")
            elif pr.reputation == ReputationLevel.SUSPICIOUS:
                has_suspicious = True
                tags.add(f"{pr.provider_name}:suspicious")

            # Extract tags from provider details
            if "tags" in pr.details and isinstance(pr.details["tags"], list):
                for t in pr.details["tags"][:3]:
                    tags.add(str(t).lower())
            if "malware_families" in pr.details and isinstance(pr.details["malware_families"], list):
                for mf in pr.details["malware_families"][:3]:
                    tags.add(str(mf).lower())
            if pr.details.get("in_cisa_kev"):
                tags.add("cisa-kev")
                tags.add("known-exploited")

        # Determine overall reputation level
        if has_malicious or max_risk >= 75.0:
            reputation = ReputationLevel.MALICIOUS
            summary = f"Flagged as MALICIOUS by {primary_provider or 'threat intelligence'} with risk score {max_risk:.1f}/100."
        elif has_suspicious or max_risk >= 35.0:
            reputation = ReputationLevel.SUSPICIOUS
            summary = f"Flagged as SUSPICIOUS with elevated risk score {max_risk:.1f}/100."
        elif any(pr.reputation == ReputationLevel.BENIGN for pr in provider_results):
            reputation = ReputationLevel.BENIGN
            summary = "Evaluated as BENIGN across active threat intelligence providers."
        else:
            reputation = ReputationLevel.UNKNOWN
            summary = "No threat indicators detected in active databases."

        return EnrichedIndicator(
            indicator=indicator,
            indicator_type=indicator_type,
            overall_reputation=reputation,
            overall_risk_score=max_risk,
            max_confidence=max_conf,
            provider_results=provider_results,
            primary_provider=primary_provider,
            cached=False,
            tags=list(tags),
            summary=summary,
            extracted_from=source_context,
        )

    def _record_recent(self, enriched: EnrichedIndicator, source_context: str | None) -> None:
        with self._cache_lock:
            record = {
                "indicator": enriched.indicator,
                "type": enriched.indicator_type.value,
                "reputation": enriched.overall_reputation.value,
                "risk_score": enriched.overall_risk_score,
                "confidence": enriched.max_confidence,
                "primary_provider": enriched.primary_provider,
                "cached": enriched.cached,
                "tags": enriched.tags,
                "summary": enriched.summary,
                "extracted_from": source_context,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self._recent_indicators.insert(0, record)
            if len(self._recent_indicators) > self._max_recent:
                self._recent_indicators.pop()

    def get_recent_indicators(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._cache_lock:
            return list(self._recent_indicators[:limit])

    def get_stats(self) -> dict[str, Any]:
        total_lookups = self.cache_hits + self.cache_misses
        hit_rate = round((self.cache_hits / total_lookups * 100.0), 1) if total_lookups > 0 else 0.0
        return {
            "total_indicators_enriched": self.total_indicators_enriched,
            "total_lookups": total_lookups,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate_pct": hit_rate,
            "active_providers_count": len([p for p in self._providers.values() if p.status in (ProviderStatus.ONLINE, ProviderStatus.NO_KEY)]),
            "total_providers": len(self._providers),
        }
