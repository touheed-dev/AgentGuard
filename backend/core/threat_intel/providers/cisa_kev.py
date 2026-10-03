import threading
import time
from typing import Any
import httpx

from backend.core.threat_intel.models import IndicatorType, ProviderResult, ReputationLevel
from backend.core.threat_intel.providers.base import ThreatIntelProvider

# Built-in seed of critical Known Exploited Vulnerabilities for sub-millisecond local lookups
SEED_KEV_VULNS: dict[str, dict[str, Any]] = {
    "CVE-2021-44228": {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j",
        "vulnerabilityName": "Apache Log4j Remote Code Execution Vulnerability (Log4Shell)",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability involving JNDI features.",
        "requiredAction": "Apply updates per vendor instructions.",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2023-34362": {
        "cveID": "CVE-2023-34362",
        "vendorProject": "Progress",
        "product": "MOVEit Transfer",
        "vulnerabilityName": "Progress MOVEit Transfer SQL Injection Vulnerability",
        "dateAdded": "2023-06-02",
        "shortDescription": "Progress MOVEit Transfer contains a SQL injection vulnerability that could allow unauthenticated privilege escalation.",
        "requiredAction": "Apply patches immediately.",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2024-3400": {
        "cveID": "CVE-2024-3400",
        "vendorProject": "Palo Alto Networks",
        "product": "PAN-OS",
        "vulnerabilityName": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "dateAdded": "2024-04-12",
        "shortDescription": "Command injection in GlobalProtect feature of PAN-OS enables unauthenticated root code execution.",
        "requiredAction": "Apply vendor mitigations and patches.",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2023-23397": {
        "cveID": "CVE-2023-23397",
        "vendorProject": "Microsoft",
        "product": "Outlook",
        "vulnerabilityName": "Microsoft Outlook Privilege Escalation Vulnerability",
        "dateAdded": "2023-03-14",
        "shortDescription": "Microsoft Outlook privilege escalation vulnerability allows NTLM credential relay.",
        "requiredAction": "Apply monthly security updates.",
        "knownRansomwareCampaignUse": "Known",
    },
    "CVE-2023-22515": {
        "cveID": "CVE-2023-22515",
        "vendorProject": "Atlassian",
        "product": "Confluence Data Center and Server",
        "vulnerabilityName": "Atlassian Confluence Data Center and Server Broken Access Control",
        "dateAdded": "2023-10-04",
        "shortDescription": "Broken access control vulnerability in Confluence allows unauthorized admin account creation.",
        "requiredAction": "Upgrade to fixed versions.",
        "knownRansomwareCampaignUse": "Known",
    },
}


class CISAKEVProvider(ThreatIntelProvider):
    """
    CISA Known Exploited Vulnerabilities (KEV) Catalog Provider.
    Official Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    """

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, fetch_live_catalog: bool = False):
        super().__init__(
            name="cisa_kev",
            display_name="CISA KEV Catalog",
            supported_types=[IndicatorType.CVE],
            is_free_tier=True,
        )
        self._catalog: dict[str, dict[str, Any]] = dict(SEED_KEV_VULNS)
        self._last_catalog_fetch: float = time.time()
        self._ttl_seconds: float = 86400.0
        self._lock = threading.Lock()

        if fetch_live_catalog:
            threading.Thread(target=self._background_fetch, daemon=True).start()

    @property
    def has_api_key(self) -> bool:
        return True  # Public official US CISA feed

    def _background_fetch(self) -> None:
        try:
            with httpx.Client(timeout=4.0) as client:
                resp = client.get(self.FEED_URL, headers={"User-Agent": "AgentGuard-ThreatIntel/1.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    new_catalog: dict[str, dict[str, Any]] = {}
                    for v in vulnerabilities:
                        cve_id = v.get("cveID")
                        if cve_id:
                            new_catalog[cve_id.upper()] = v
                    if new_catalog:
                        with self._lock:
                            self._catalog = new_catalog
                            self._last_catalog_fetch = time.time()
        except Exception:
            pass

    def _lookup(self, indicator: str, indicator_type: IndicatorType) -> ProviderResult:
        cve_key = indicator.strip().upper()

        with self._lock:
            vuln_info = self._catalog.get(cve_key)

        if vuln_info:
            ransomware = vuln_info.get("knownRansomwareCampaignUse", "Unknown")
            is_ransomware = ransomware.lower() == "known"

            details = {
                "cve_id": cve_key,
                "vendor_project": vuln_info.get("vendorProject", "Unknown"),
                "product": vuln_info.get("product", "Unknown"),
                "vulnerability_name": vuln_info.get("vulnerabilityName", ""),
                "date_added": vuln_info.get("dateAdded", ""),
                "short_description": vuln_info.get("shortDescription", ""),
                "required_action": vuln_info.get("requiredAction", ""),
                "known_ransomware_campaign_use": ransomware,
                "in_cisa_kev": True,
            }

            risk = 95.0 if is_ransomware else 90.0
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.MALICIOUS,
                risk_score=risk,
                confidence=1.0,
                details=details,
                raw_data=vuln_info,
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_key}",
            )
        else:
            return self._build_result(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=ReputationLevel.BENIGN,
                risk_score=0.0,
                confidence=0.7,
                details={
                    "cve_id": cve_key,
                    "in_cisa_kev": False,
                    "message": "Vulnerability is not currently listed in the CISA Known Exploited Vulnerabilities catalog.",
                },
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_key}",
            )
