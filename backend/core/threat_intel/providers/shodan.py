import os
from typing import Any
import httpx

from backend.core.threat_intel.models import IndicatorType, ProviderResult, ReputationLevel
from backend.core.threat_intel.providers.base import ThreatIntelProvider


class ShodanProvider(ThreatIntelProvider):
    """
    Shodan IP Intelligence Provider.
    Official API: https://api.shodan.io/shodan/host/{ip}
    """

    BASE_URL = "https://api.shodan.io/shodan/host"

    def __init__(self, api_key: str | None = None):
        super().__init__(
            name="shodan",
            display_name="Shodan",
            supported_types=[IndicatorType.IP],
            is_free_tier=False,
        )
        self._api_key = api_key or os.getenv("SHODAN_API_KEY", "")

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
                details={"message": "No Shodan API key configured (set SHODAN_API_KEY)."},
                source_url="https://www.shodan.io",
            )

        endpoint = f"{self.BASE_URL}/{indicator}"
        params = {"key": self._api_key}

        with httpx.Client(timeout=1.5) as client:
            resp = client.get(endpoint, params=params)
            if resp.status_code == 429:
                self.rate_limit_info = "Shodan query credit limit reached"
                raise RuntimeError("Shodan rate limit reached")
            if resp.status_code in (401, 403):
                raise RuntimeError("Invalid Shodan API key or unauthorized")
            if resp.status_code == 404:
                return self._build_result(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    reputation=ReputationLevel.BENIGN,
                    risk_score=0.0,
                    confidence=0.7,
                    details={"message": "No Shodan records found for IP"},
                    source_url=f"https://www.shodan.io/host/{indicator}",
                )
            resp.raise_for_status()
            data = resp.json()

        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        tags = data.get("tags", [])
        org = data.get("org", "Unknown")
        isp = data.get("isp", "Unknown")
        country = data.get("country_name", "Unknown")

        has_critical_vulns = len(vulns) > 0
        is_compromised_tag = any(t in tags for t in ("compromised", "malware", "c2", "tor", "vpn"))

        if is_compromised_tag or len(vulns) >= 3:
            reputation = ReputationLevel.MALICIOUS
            risk = 85.0
            confidence = 0.9
        elif has_critical_vulns or len(ports) > 10:
            reputation = ReputationLevel.SUSPICIOUS
            risk = 55.0
            confidence = 0.75
        else:
            reputation = ReputationLevel.BENIGN
            risk = 10.0
            confidence = 0.8

        details = {
            "ports": ports[:15],
            "vulns": list(vulns)[:10] if isinstance(vulns, (list, set)) else [],
            "tags": tags,
            "org": org,
            "isp": isp,
            "country_name": country,
            "hostnames": data.get("hostnames", [])[:5],
        }

        return self._build_result(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=reputation,
            risk_score=risk,
            confidence=confidence,
            details=details,
            raw_data={"ports": ports, "vulns": list(vulns) if isinstance(vulns, (list, set)) else []},
            source_url=f"https://www.shodan.io/host/{indicator}",
        )
