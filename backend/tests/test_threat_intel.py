import pytest
from backend.core.threat_intel.extractors import IndicatorExtractor
from backend.core.threat_intel.models import IndicatorType, ReputationLevel
from backend.core.threat_intel.providers.cisa_kev import CISAKEVProvider
from backend.core.threat_intel.service import ThreatIntelService


def test_indicator_extractor_ipv4_and_url():
    text = "Sending telemetry to http://194.26.29.112:8080/c2 and https://evil-domain.com/path?query=1"
    extracted = IndicatorExtractor.extract_from_text(text)
    values = {e.value for e in extracted}
    types = {e.indicator_type for e in extracted}

    assert "http://194.26.29.112:8080/c2" in values
    assert "https://evil-domain.com/path?query=1" in values
    assert "194.26.29.112" in values
    assert "evil-domain.com" in values
    assert IndicatorType.URL in types
    assert IndicatorType.IP in types
    assert IndicatorType.DOMAIN in types


def test_indicator_extractor_cve_and_hashes():
    text = "Vulnerability CVE-2021-44228 detected in payload hash 44d88612fea8a8f36de82e1278abb02f"
    extracted = IndicatorExtractor.extract_from_text(text)
    values = {e.value for e in extracted}

    assert "CVE-2021-44228" in values
    assert "44d88612fea8a8f36de82e1278abb02f" in values


def test_cisa_kev_provider_known_vuln():
    provider = CISAKEVProvider()
    result = provider.query("CVE-2021-44228", IndicatorType.CVE)
    assert result.reputation == ReputationLevel.MALICIOUS
    assert result.risk_score >= 90.0
    assert result.confidence == 1.0
    assert result.details["in_cisa_kev"] is True
    assert "Log4j" in result.details["vulnerability_name"]


def test_cisa_kev_provider_unknown_vuln():
    provider = CISAKEVProvider()
    result = provider.query("CVE-1990-0001", IndicatorType.CVE)
    assert result.reputation == ReputationLevel.BENIGN
    assert result.risk_score == 0.0
    assert result.details["in_cisa_kev"] is False


def test_threat_intel_service_caching_and_enrichment():
    service = ThreatIntelService(providers=[CISAKEVProvider()])
    # First query (cache miss)
    enriched_1 = service.enrich_indicator("CVE-2021-44228", IndicatorType.CVE)
    assert enriched_1.overall_reputation == ReputationLevel.MALICIOUS
    assert enriched_1.cached is False

    # Second query (cache hit)
    enriched_2 = service.enrich_indicator("CVE-2021-44228", IndicatorType.CVE)
    assert enriched_2.cached is True
    assert service.cache_hits >= 1


def test_threat_intel_enrich_action():
    service = ThreatIntelService(providers=[CISAKEVProvider()])
    args = {
        "command": "patch CVE-2021-44228",
        "target": "CVE-2021-44228",
    }
    enriched_list = service.enrich_action("bash_command", args)
    assert len(enriched_list) >= 1
    assert any(e.indicator_type == IndicatorType.CVE for e in enriched_list)
