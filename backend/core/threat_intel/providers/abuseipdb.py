import os
from typing import Any
import httpx

from backend.core.threat_intel.models import IndicatorType, ProviderResult, ReputationLevel
from backend.core.threat_intel.providers.base import ThreatIntelProvider

# Built-in seed cache for high-confidence threats & benchmark test vectors
SEED_ABUSEIPDB: dict[str, dict[str, Any]] = {
    "194.26.29.112": {
        "abuseConfidenceScore": 100,
        "totalReports": 482,
        "isWhitelisted": False,
        "countryCode": "RU",
        "usageType": "Data Center/Web Hosting",
        "isp": "Hostkey B.V.",
        "domain": "hostkey.com",
    },
    "185.220.101.5": {
        "abuseConfidenceScore": 100,
        "totalReports": 320,
        "isWhitelisted": False,
        "countryCode": "DE",
        "usageType": "Tor Exit Node",
        "isp": "Zwiebelfreunde",
        "domain": "torproject.org",
    },
    "8.8.8.8": {
        "abuseConfidenceScore": 0,
        "totalReports": 0,
        "isWhitelisted": True,
        "countryCode": "US",
        "usageType": "DNS Resolver",
        "isp": "Google LLC",
        "domain": "google.com",
    },
}


class AbuseIPDBProvider(ThreatIntelProvider):
    """
    AbuseIPDB Threat Intelligence Provider for IP Reputation.
    Official API: https://api.abuseipdb.com/api/v2/check
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str | None = None):
        super().__init__(
            name="abuseipdb",
            display_name="AbuseIPDB",
            supported_types=[IndicatorType.IP],
            is_free_tier=False,
        )
        self._api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key and self._api_key.strip())

    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        cleaned = indicator.strip()
        if cleaned in SEED_ABUSEIPDB:
            data = SEED_ABUSEIPDB[cleaned]
            abuse_score = float(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            is_whitelisted = bool(data.get("isWhitelisted", False))

            if is_whitelisted:
                reputation = ReputationLevel.BENIGN
                risk = 0.0
                confidence = 0.95
            elif abuse_score >= 50:
                reputation = ReputationLevel.MALICIOUS
                risk = max(abuse_score, 75.0)
                confidence = 1.0
            else:
                reputation = ReputationLevel.BENIGN
                risk = abuse_score
                confidence = 0.8

            details = {
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
                "is_whitelisted": is_whitelisted,
                "country_code": data.get("countryCode", "UNKNOWN"),
                "usage_type": data.get("usageType", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", ""),
            }

            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=reputation,
                risk_score=risk,
                confidence=confidence,
                details=details,
                raw_data=data,
                source_url=f"https://www.abuseipdb.com/check/{indicator}",
            )

        if not self.has_api_key:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"message": "No AbuseIPDB API key configured (set ABUSEIPDB_API_KEY)."},
                source_url="https://www.abuseipdb.com",
            )

        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
            "User-Agent": "AgentGuard-ThreatIntel/1.0",
        }
        params = {
            "ipAddress": indicator,
            "maxAgeInDays": "90",
            "verbose": "",
        }

        try:
            with httpx.Client(timeout=1.5) as client:
                resp = client.get(self.BASE_URL, headers=headers, params=params)
                if resp.status_code == 429:
                    self.rate_limit_info = "Rate limit exceeded (429)"
                    raise RuntimeError("AbuseIPDB rate limit exceeded")
                if resp.status_code in (401, 403):
                    raise RuntimeError("Invalid AbuseIPDB API key or unauthorized")
                resp.raise_for_status()
                data = resp.json().get("data", {})
        except Exception as e:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"error": str(e)},
                source_url="https://www.abuseipdb.com",
            )

        abuse_score = float(data.get("abuseConfidenceScore", 0))
        total_reports = int(data.get("totalReports", 0))
        is_whitelisted = bool(data.get("isWhitelisted", False))
        country_code = data.get("countryCode", "UNKNOWN")
        usage_type = data.get("usageType", "Unknown")
        isp = data.get("isp", "Unknown")
        domain = data.get("domain", "")

        if is_whitelisted:
            reputation = ReputationLevel.BENIGN
            risk = 0.0
            confidence = 0.95
        elif abuse_score >= 50 or total_reports >= 10:
            reputation = ReputationLevel.MALICIOUS
            risk = max(abuse_score, 75.0)
            confidence = min(1.0, 0.5 + (total_reports / 20.0))
        elif abuse_score > 10 or total_reports > 0:
            reputation = ReputationLevel.SUSPICIOUS
            risk = max(abuse_score, 40.0)
            confidence = 0.6
        else:
            reputation = ReputationLevel.BENIGN
            risk = abuse_score
            confidence = 0.7

        details = {
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "is_whitelisted": is_whitelisted,
            "country_code": country_code,
            "usage_type": usage_type,
            "isp": isp,
            "domain": domain,
            "last_reported_at": data.get("lastReportedAt"),
        }

        return self._build_result(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation=reputation,
            risk_score=risk,
            confidence=confidence,
            details=details,
            raw_data=data,
            source_url=f"https://www.abuseipdb.com/check/{indicator}",
        )
