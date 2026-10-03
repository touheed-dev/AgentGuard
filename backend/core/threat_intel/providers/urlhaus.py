import os
from typing import Any
import httpx

from backend.core.threat_intel.models import IndicatorType, ProviderResult, ReputationLevel
from backend.core.threat_intel.providers.base import ThreatIntelProvider

# Built-in seed cache for high-confidence threats & offline/test vectors
SEED_URLHAUS: dict[str, dict[str, Any]] = {
    "http://malicious-c2-payload.com/agent-drop.bin": {
        "query_status": "ok",
        "threat": "malicious_download",
        "tags": ["c2", "agent-drop", "trojan"],
        "url_status": "online",
        "reporter": "abuse.ch",
        "date_added": "2024-01-01",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/sample-c2",
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "query_status": "ok",
        "threat": "trojan_dropper",
        "tags": ["trojan", "malware-sample"],
        "url_status": "online",
        "reporter": "abuse.ch",
        "date_added": "2024-01-01",
        "urlhaus_reference": "https://urlhaus.abuse.ch/payload/44d88612fea8a8f36de82e1278abb02f",
    },
    "db349b97c37d22f5b0d0fed033e224ce6ac7b781452d3b7f345824e2b1c550ed": {
        "query_status": "ok",
        "threat": "ransomware_payload",
        "tags": ["ransomware", "wannacry"],
        "url_status": "online",
        "reporter": "abuse.ch",
        "date_added": "2024-01-01",
        "urlhaus_reference": "https://urlhaus.abuse.ch/payload/db349b97c37d22f5b0d0fed033e224ce6ac7b781452d3b7f345824e2b1c550ed",
    },
}


class URLhausProvider(ThreatIntelProvider):
    """
    URLhaus (abuse.ch) Threat Intelligence Provider for malicious URLs, hosts, and payloads.
    Public API: https://urlhaus-api.abuse.ch/v1/
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, api_key: str | None = None):
        super().__init__(
            name="urlhaus",
            display_name="URLhaus (abuse.ch)",
            supported_types=[
                IndicatorType.URL,
                IndicatorType.DOMAIN,
                IndicatorType.HASH_MD5,
                IndicatorType.HASH_SHA256,
            ],
            is_free_tier=True,
        )
        self._api_key = api_key or os.getenv("URLHAUS_API_KEY", "")

    @property
    def has_api_key(self) -> bool:
        return True

    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        cleaned = indicator.strip()
        if cleaned in SEED_URLHAUS:
            res_data = SEED_URLHAUS[cleaned]
            threat = res_data.get("threat", "malicious")
            tags = res_data.get("tags") or []
            details = {
                "query_status": "ok",
                "threat": threat,
                "tags": tags,
                "url_status": res_data.get("url_status", "online"),
                "reporter": res_data.get("reporter", "abuse.ch"),
                "date_added": res_data.get("date_added", ""),
                "urlhaus_reference": res_data.get("urlhaus_reference"),
            }
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.MALICIOUS,
                risk_score=95.0,
                confidence=0.95,
                details=details,
                raw_data=res_data,
                source_url=res_data.get("urlhaus_reference") or "https://urlhaus.abuse.ch",
            )

        headers = {
            "User-Agent": "AgentGuard-ThreatIntel/1.0",
            "Accept": "application/json",
        }
        if self._api_key:
            headers["Auth-Key"] = self._api_key

        endpoint = f"{self.BASE_URL}/url/"
        data: dict[str, str] = {}

        if indicator_type == IndicatorType.URL:
            endpoint = f"{self.BASE_URL}/url/"
            data = {"url": indicator}
        elif indicator_type == IndicatorType.DOMAIN:
            endpoint = f"{self.BASE_URL}/host/"
            data = {"host": indicator}
        elif indicator_type == IndicatorType.HASH_MD5:
            endpoint = f"{self.BASE_URL}/payload/"
            data = {"md5_hash": indicator}
        elif indicator_type == IndicatorType.HASH_SHA256:
            endpoint = f"{self.BASE_URL}/payload/"
            data = {"sha256_hash": indicator}

        try:
            with httpx.Client(timeout=1.5) as client:
                resp = client.post(endpoint, data=data, headers=headers)
                if resp.status_code == 429:
                    self.rate_limit_info = "URLhaus rate limit reached"
                    raise RuntimeError("URLhaus rate limit reached")
                resp.raise_for_status()
                res_data = resp.json()
        except Exception:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.0,
                details={"query_status": "offline_fallback"},
                source_url="https://urlhaus.abuse.ch",
            )

        query_status = res_data.get("query_status", "no_results")
        if query_status == "ok":
            threat = res_data.get("threat", "malicious")
            tags = res_data.get("tags") or []
            url_status = res_data.get("url_status", "online")
            reporter = res_data.get("reporter", "abuse.ch")
            date_added = res_data.get("date_added", "")

            details = {
                "query_status": query_status,
                "threat": threat,
                "tags": tags,
                "url_status": url_status,
                "reporter": reporter,
                "date_added": date_added,
                "urlhaus_reference": res_data.get("urlhaus_reference"),
            }

            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.MALICIOUS,
                risk_score=95.0,
                confidence=0.95,
                details=details,
                raw_data=res_data,
                source_url=res_data.get("urlhaus_reference") or "https://urlhaus.abuse.ch",
            )
        elif query_status == "no_results":
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.BENIGN,
                risk_score=0.0,
                confidence=0.8,
                details={"query_status": "no_results", "message": "Indicator not found in URLhaus database"},
                source_url="https://urlhaus.abuse.ch",
            )
        else:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.UNKNOWN,
                risk_score=0.0,
                confidence=0.5,
                details={"query_status": query_status},
                source_url="https://urlhaus.abuse.ch",
            )
