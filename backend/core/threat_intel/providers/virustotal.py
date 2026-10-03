import base64
import os
from typing import Any
import httpx

from backend.core.threat_intel.models import IndicatorType, ProviderResult, ReputationLevel
from backend.core.threat_intel.providers.base import ThreatIntelProvider


class VirusTotalProvider(ThreatIntelProvider):
    """
    VirusTotal API v3 Provider.
    Official API: https://www.virustotal.com/api/v3/
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None):
        super().__init__(
            name="virustotal",
            display_name="VirusTotal",
            supported_types=[
                IndicatorType.IP,
                IndicatorType.DOMAIN,
                IndicatorType.URL,
                IndicatorType.HASH_MD5,
                IndicatorType.HASH_SHA1,
                IndicatorType.HASH_SHA256,
            ],
            is_free_tier=False,
        )
        self._api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key and self._api_key.strip())

    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        if not self.has_api_key:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"message": "No VirusTotal API key configured (set VIRUSTOTAL_API_KEY)."},
                source_url="https://www.virustotal.com",
            )

        endpoint = f"{self.BASE_URL}/ip_addresses/{indicator}"
        if indicator_type == IndicatorType.DOMAIN:
            endpoint = f"{self.BASE_URL}/domains/{indicator}"
        elif indicator_type == IndicatorType.URL:
            # VT requires base64-encoded URL without padding
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            endpoint = f"{self.BASE_URL}/urls/{url_id}"
        elif indicator_type in (IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256):
            endpoint = f"{self.BASE_URL}/files/{indicator}"

        headers = {
            "x-apikey": self._api_key,
            "Accept": "application/json",
            "User-Agent": "AgentGuard-ThreatIntel/1.0",
        }

        with httpx.Client(timeout=1.5) as client:
            resp = client.get(endpoint, headers=headers)
            if resp.status_code == 429:
                self.rate_limit_info = "VirusTotal rate limit reached"
                raise RuntimeError("VirusTotal rate limit reached")
            if resp.status_code in (401, 403):
                raise RuntimeError("Invalid VirusTotal API key or unauthorized")
            if resp.status_code == 404:
                return self._build_result(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    reputation=ReputationLevel.BENIGN,
                    risk_score=0.0,
                    confidence=0.6,
                    details={"message": "Indicator not found in VirusTotal database"},
                    source_url="https://www.virustotal.com",
                )
            resp.raise_for_status()
            data = resp.json().get("data", {})

        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious_count = int(stats.get("malicious", 0))
        suspicious_count = int(stats.get("suspicious", 0))
        harmless_count = int(stats.get("harmless", 0))
        undetected_count = int(stats.get("undetected", 0))
        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

        if malicious_count >= 3:
            reputation = ReputationLevel.MALICIOUS
            risk = min(100.0, 75.0 + (malicious_count * 3.0))
            confidence = min(1.0, 0.7 + (malicious_count / 20.0))
        elif malicious_count > 0 or suspicious_count >= 2:
            reputation = ReputationLevel.SUSPICIOUS
            risk = min(74.0, 35.0 + (malicious_count * 15.0) + (suspicious_count * 5.0))
            confidence = 0.75
        else:
            reputation = ReputationLevel.BENIGN
            risk = 0.0
            confidence = 0.85

        details = {
            "malicious_engines": malicious_count,
            "suspicious_engines": suspicious_count,
            "harmless_engines": harmless_count,
            "total_engines": total_engines,
            "reputation_score": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
        }

        return self._build_result(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=reputation,
            risk_score=risk,
            confidence=confidence,
            details=details,
            raw_data=stats,
            source_url=f"https://www.virustotal.com/gui/search/{indicator}",
        )
