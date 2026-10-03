import os
from typing import Any
import httpx

from backend.core.threat_intel.models import IndicatorType, ProviderResult, ReputationLevel
from backend.core.threat_intel.providers.base import ThreatIntelProvider

# Built-in seed cache for high-confidence internet noise & scanner actors
SEED_GREYNOISE: dict[str, dict[str, Any]] = {
    "198.235.24.1": {
        "noise": True,
        "riot": False,
        "classification": "unknown",
        "actor": "Internet Mass Scanner",
        "name": "Mass Reconnaissance Scanner",
    },
    "185.180.143.10": {
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "actor": "Mirai Botnet Scanner",
        "name": "Malicious IoT Scanner",
    },
    "1.1.1.1": {
        "noise": False,
        "riot": True,
        "classification": "benign",
        "actor": "Cloudflare",
        "name": "Cloudflare DNS",
    },
}


class GreyNoiseProvider(ThreatIntelProvider):
    """
    GreyNoise Community & Enterprise IP Intelligence Provider.
    Official API: https://api.greynoise.io/v3/community/{ip}
    """

    BASE_URL = "https://api.greynoise.io/v3/community"

    def __init__(self, api_key: str | None = None):
        super().__init__(
            name="greynoise",
            display_name="GreyNoise",
            supported_types=[IndicatorType.IP],
            is_free_tier=False,
        )
        self._api_key = api_key or os.getenv("GREYNOISE_API_KEY", "")

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key and self._api_key.strip())

    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        cleaned = indicator.strip()
        if cleaned in SEED_GREYNOISE:
            data = SEED_GREYNOISE[cleaned]
            noise = bool(data.get("noise", False))
            riot = bool(data.get("riot", False))
            classification = str(data.get("classification", "unknown")).lower()
            actor = data.get("actor", "unknown")
            name = data.get("name", "")

            if riot:
                reputation = ReputationLevel.BENIGN
                risk = 0.0
                confidence = 0.95
            elif classification == "malicious":
                reputation = ReputationLevel.MALICIOUS
                risk = 90.0
                confidence = 0.95
            elif noise:
                reputation = ReputationLevel.SUSPICIOUS
                risk = 45.0
                confidence = 0.8
            else:
                reputation = ReputationLevel.BENIGN
                risk = 0.0
                confidence = 0.8

            details = {
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "actor": actor,
                "name": name,
            }

            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=reputation,
                risk_score=risk,
                confidence=confidence,
                details=details,
                raw_data=data,
                source_url=f"https://viz.greynoise.io/ip/{indicator}",
            )

        if not self.has_api_key:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"message": "No GreyNoise API key configured (set GREYNOISE_API_KEY)."},
                source_url="https://viz.greynoise.io",
            )

        endpoint = f"{self.BASE_URL}/{indicator}"
        headers = {
            "key": self._api_key,
            "Accept": "application/json",
            "User-Agent": "AgentGuard-ThreatIntel/1.0",
        }

        try:
            with httpx.Client(timeout=1.5) as client:
                resp = client.get(endpoint, headers=headers)
                if resp.status_code == 429:
                    self.rate_limit_info = "GreyNoise rate limit reached"
                    raise RuntimeError("GreyNoise rate limit reached")
                if resp.status_code in (401, 403):
                    raise RuntimeError("Invalid GreyNoise API key or unauthorized")
                if resp.status_code == 404:
                    return self._build_result(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        reputation=ReputationLevel.BENIGN,
                        risk_score=0.0,
                        confidence=0.7,
                        details={"noise": False, "riot": False, "message": "IP not observed scanning the internet"},
                        source_url=f"https://viz.greynoise.io/ip/{indicator}",
                    )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"error": str(e)},
                source_url="https://viz.greynoise.io",
            )

        noise = bool(data.get("noise", False))
        riot = bool(data.get("riot", False))
        classification = str(data.get("classification", "unknown")).lower()
        actor = data.get("actor", "unknown")
        name = data.get("name", "")

        if riot:
            reputation = ReputationLevel.BENIGN
            risk = 0.0
            confidence = 0.95
        elif classification == "malicious":
            reputation = ReputationLevel.MALICIOUS
            risk = 90.0
            confidence = 0.95
        elif classification == "benign":
            reputation = ReputationLevel.BENIGN
            risk = 10.0
            confidence = 0.85
        elif noise:
            reputation = ReputationLevel.SUSPICIOUS
            risk = 45.0
            confidence = 0.75
        else:
            reputation = ReputationLevel.UNKNOWN
            risk = 0.0
            confidence = 0.5

        details = {
            "noise": noise,
            "riot": riot,
            "classification": classification,
            "actor": actor,
            "name": name,
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }

        return self._build_result(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=reputation,
            risk_score=risk,
            confidence=confidence,
            details=details,
            raw_data=data,
            source_url=f"https://viz.greynoise.io/ip/{indicator}",
        )
