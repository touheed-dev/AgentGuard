import pytest
from backend.apps.gateway.runtime import create_runtime
from backend.core.benchmark.service import BenchmarkService, calculate_percentiles


def test_calculate_percentiles():
    values = [10.0, 20.0, 30.0, 40.0, 50.0, 100.0]
    res = calculate_percentiles(values)
    assert res["min"] == 10.0
    assert res["max"] == 100.0
    assert res["avg"] == 41.67
    assert res["p50"] == 30.0
    assert res["p95"] == 100.0


def test_benchmark_service_record_and_metrics():
    bench = BenchmarkService()
    bench.record_event("researcher-01", "echo", "ALLOW", 12.5, 0.0, 0, risk_score=10.0)
    bench.record_event("coder-01", "bash_command", "BLOCK", 18.2, 5.0, 1, risk_score=95.0)

    metrics = bench.get_live_metrics()
    assert metrics["total_events_evaluated"] == 2
    assert metrics["decisions"]["ALLOW"] == 1
    assert metrics["decisions"]["BLOCK"] == 1
    assert metrics["gateway_latency_ms"]["min"] == 12.5
    assert metrics["gateway_latency_ms"]["max"] == 18.2


def test_benchmark_run_scenario_clean_and_malicious():
    gateway, identity_service, _ = create_runtime()
    bench = BenchmarkService()

    # Run clean echo scenario
    res_clean = bench.run_scenario("scenario-clean-echo", gateway, identity_service)
    assert res_clean["actual_decision"] == "ALLOW"
    assert res_clean["decision_matched"] is True

    # Run cve exploit scenario
    res_cve = bench.run_scenario("scenario-cisa-kev-cve", gateway, identity_service)
    assert res_cve["actual_decision"] == "BLOCK"
    assert res_cve["decision_matched"] is True

    # Run honeytoken scenario
    res_honey = bench.run_scenario("scenario-honeytoken-trap", gateway, identity_service)
    assert res_honey["actual_decision"] == "BLOCK"
    assert res_honey["decision_matched"] is True
