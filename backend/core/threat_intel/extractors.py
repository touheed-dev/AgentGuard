import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from backend.core.threat_intel.models import IndicatorType

# Regex patterns for high-precision extraction
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*:[0-9a-fA-F]{1,4}\b"
)
URL_PATTERN = re.compile(r"\bhttps?://[a-zA-Z0-9\-\._~:/\?#\[\]@!$&'\(\)\*\+,;=%]+\b", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Common benign domain extensions / noise to avoid misclassifying code tokens like "os.path"
COMMON_IGNORED_DOMAINS = {
    "os.path", "sys.path", "example.com", "localhost", "local", "internal",
    "test.com", "schema.json", "format.json", "index.html", "data.json",
    "main.py", "test.py", "config.json"
}


def is_valid_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        # We can extract all IPs, but note if private
        return True
    except ipaddress.AddressValueError:
        return False


def is_valid_ipv6(ip_str: str) -> bool:
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except ipaddress.AddressValueError:
        return False


class ExtractedIndicator:
    def __init__(self, value: str, indicator_type: IndicatorType, source_context: str | None = None):
        self.value = value.strip()
        self.indicator_type = indicator_type
        self.source_context = source_context

    def __repr__(self) -> str:
        return f"<ExtractedIndicator {self.indicator_type.value}: {self.value}>"

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ExtractedIndicator):
            return False
        return self.value.lower() == other.value.lower() and self.indicator_type == other.indicator_type

    def __hash__(self) -> int:
        return hash((self.value.lower(), self.indicator_type))


class IndicatorExtractor:
    """
    Extracts security indicators (IPs, Domains, URLs, Hashes, CVEs) from
    arbitrary strings, dictionaries, and nested tool arguments.
    """

    @classmethod
    def extract_from_text(cls, text: str, context: str | None = None) -> list[ExtractedIndicator]:
        if not text or not isinstance(text, str):
            return []

        results: list[ExtractedIndicator] = []
        seen: set[tuple[str, IndicatorType]] = set()

        # 1. Extract URLs first so we don't double-count broken substrings
        urls = URL_PATTERN.findall(text)
        for u in urls:
            cleaned_url = u.rstrip(".,;)\"'>")
            key = (cleaned_url.lower(), IndicatorType.URL)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIndicator(cleaned_url, IndicatorType.URL, context))

            # Also extract hostname/domain from URL
            try:
                parsed = urlparse(cleaned_url)
                if parsed.hostname and not is_valid_ipv4(parsed.hostname):
                    dom = parsed.hostname.lower()
                    if dom not in COMMON_IGNORED_DOMAINS and "." in dom:
                        dom_key = (dom, IndicatorType.DOMAIN)
                        if dom_key not in seen:
                            seen.add(dom_key)
                            results.append(ExtractedIndicator(dom, IndicatorType.DOMAIN, f"Extracted from {cleaned_url}"))
                elif parsed.hostname and is_valid_ipv4(parsed.hostname):
                    ip_key = (parsed.hostname, IndicatorType.IP)
                    if ip_key not in seen:
                        seen.add(ip_key)
                        results.append(ExtractedIndicator(parsed.hostname, IndicatorType.IP, f"Extracted from {cleaned_url}"))
            except Exception:
                pass

        # 2. Extract IPv4
        for ip_match in IPV4_PATTERN.findall(text):
            if is_valid_ipv4(ip_match):
                key = (ip_match, IndicatorType.IP)
                if key not in seen:
                    seen.add(key)
                    results.append(ExtractedIndicator(ip_match, IndicatorType.IP, context))

        # 3. Extract IPv6
        for ip6_match in IPV6_PATTERN.findall(text):
            if is_valid_ipv6(ip6_match):
                key = (ip6_match.lower(), IndicatorType.IP)
                if key not in seen:
                    seen.add(key)
                    results.append(ExtractedIndicator(ip6_match.lower(), IndicatorType.IP, context))

        # 4. Extract CVEs
        for cve_match in CVE_PATTERN.findall(text):
            cve_upper = cve_match.upper()
            key = (cve_upper, IndicatorType.CVE)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIndicator(cve_upper, IndicatorType.CVE, context))

        # 5. Extract SHA256 hashes (64 hex characters)
        for sha256_match in SHA256_PATTERN.findall(text):
            key = (sha256_match.lower(), IndicatorType.HASH_SHA256)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIndicator(sha256_match.lower(), IndicatorType.HASH_SHA256, context))

        # 6. Extract SHA1 hashes (40 hex characters)
        for sha1_match in SHA1_PATTERN.findall(text):
            # Ensure not substring of a sha256 already extracted
            if any(sha1_match.lower() in r.value.lower() for r in results if r.indicator_type == IndicatorType.HASH_SHA256):
                continue
            key = (sha1_match.lower(), IndicatorType.HASH_SHA1)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIndicator(sha1_match.lower(), IndicatorType.HASH_SHA1, context))

        # 7. Extract MD5 hashes (32 hex characters)
        for md5_match in MD5_PATTERN.findall(text):
            if any(md5_match.lower() in r.value.lower() for r in results if r.indicator_type in (IndicatorType.HASH_SHA256, IndicatorType.HASH_SHA1)):
                continue
            key = (md5_match.lower(), IndicatorType.HASH_MD5)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIndicator(md5_match.lower(), IndicatorType.HASH_MD5, context))

        # 8. Extract Standalone Domains
        for dom_match in DOMAIN_PATTERN.findall(text):
            dom_lower = dom_match.lower()
            if dom_lower in COMMON_IGNORED_DOMAINS:
                continue
            if dom_lower.endswith(".py") or dom_lower.endswith(".json") or dom_lower.endswith(".ts") or dom_lower.endswith(".js"):
                continue
            key = (dom_lower, IndicatorType.DOMAIN)
            if key not in seen:
                seen.add(key)
                results.append(ExtractedIndicator(dom_lower, IndicatorType.DOMAIN, context))

        return results

    @classmethod
    def extract_from_arguments(cls, tool_name: str, arguments: dict[str, Any]) -> list[ExtractedIndicator]:
        results: list[ExtractedIndicator] = []
        seen: set[tuple[str, IndicatorType]] = set()

        def _traverse(val: Any, path: str) -> None:
            if isinstance(val, str):
                extracted = cls.extract_from_text(val, context=f"tool:{tool_name}.{path}")
                for item in extracted:
                    key = (item.value.lower(), item.indicator_type)
                    if key not in seen:
                        seen.add(key)
                        results.append(item)
            elif isinstance(val, dict):
                for k, v in val.items():
                    _traverse(v, f"{path}.{k}" if path else k)
            elif isinstance(val, (list, tuple, set)):
                for idx, item in enumerate(val):
                    _traverse(item, f"{path}[{idx}]")

        _traverse(arguments, "")
        return results
