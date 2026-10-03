import os
from typing import Any
import httpx

from backend.core.threat_intel.models import IndicatorType, ProviderResult, ReputationLevel
from backend.core.threat_intel.providers.base import ThreatIntelProvider


class OTXProvider(ThreatIntelProvider):
    """
    AlienVault Open Threat Exchange (OTX) Provider.
    Official API: https://otx.alienvault.com/api/v1/indicators/
    """

    BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, api_key: str | None = None):
        super().__init__(
            name="otx",
            display_name="AlienVault OTX",
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
        self._api_key = api_key or os.getenv("OTX_API_KEY", "")

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
                details={"message": "No AlienVault OTX API key configured (set OTX_API_KEY)."},
                source_url="https://otx.alienvault.com",
            )

        # Map type to OTX indicator section
        type_section = "IPv4"
        if indicator_type == IndicatorType.DOMAIN:
            type_section = "domain"
        elif indicator_type == IndicatorType.URL:
            type_section = "url"
        elif indicator_type in (IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256):
            type_section = "file"

        endpoint = f"{self.BASE_URL}/{type_section}/{indicator}/general"
        headers = {
            "X-OTX-API-KEY": self._api_key,
            "Accept": "application/json",
            "User-Agent": "AgentGuard-ThreatIntel/1.0",
        }

        with httpx.Client(timeout=1.5) as client:
            resp = client.get(endpoint, headers=headers)
            if resp.status_code == 429:
                self.rate_limit_info = "OTX rate limit reached"
                raise RuntimeError("OTX rate limit reached")
            if resp.status_code in (401, 403):
                raise RuntimeError("Invalid OTX API key or unauthorized")
            if resp.status_code == 404:
                return self._build_result(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    reputation=ReputationLevel.BENIGN,
                    risk_score=0.0,
                    confidence=0.7,
                    details={"pulse_count": 0, "message": "No threat pulses found in OTX"},
                    source_url=f"https://otx.alienvault.com/indicator/{type_section}/{indicator}",
                )
            resp.raise_for_status()
            data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulse_count = int(pulse_info.get("count", 0))
        pulses = pulse_info.get("pulses", [])
        pulse_names = [p.get("name") for p in pulses[:5] if p.get("name")]
        malware_families = list({tag for p in pulses for tag in p.get("tags", []) if "malware" in tag.lower()})

        if pulse_count >= 5:
            reputation = ReputationLevel.MALICIOUS
            risk = 90.0
            confidence = 0.95
        elif pulse_count > 0:
            reputation = ReputationLevel.SUSPICIOUS
            risk = min(80.0, 40.0 + (pulse_count * 10))
            confidence = 0.8
        else:
            reputation = ReputationLevel.BENIGN
            risk = 0.0
            confidence = 0.75

        details = {
            "pulse_count": pulse_count,
            "top_pulses": pulse_names,
            "malware_families": malware_families,
            "country_name": data.get("country_name"),
            "asn": data.get("asn"),
        }

        return self._build_result(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=reputation,
            risk_score=risk,
            confidence=confidence,
            details=details,
            raw_data={"pulse_count": pulse_count, "pulses": pulse_names},
            source_url=f"https://otx.alienvault.com/indicator/{type_section}/{indicator}",
        )
