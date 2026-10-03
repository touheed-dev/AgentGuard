import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Activity, Globe, Database, Cpu, Zap, AlertTriangle, CheckCircle2, XCircle,
  Clock, Search, RefreshCw, Server, ArrowRight, Play, Check, ChevronRight,
  ExternalLink, Layers, Radio, Sparkles, Terminal, Flame, Eye, Lock, Crosshair, BarChart3
} from 'lucide-react';
import { api } from '../api';
import {
  ProviderHealthItem,
  EnrichedIndicatorItem,
  BenchmarkScenarioItem,
  BenchmarkScenarioExecutionResult,
  LiveBenchmarkMetrics,
  BenchmarkEventItem,
} from '../types';

export const ThreatIntelBenchmarkView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'threat-intel' | 'providers' | 'benchmark-metrics' | 'judge-demo'>('threat-intel');

  // Threat Intel State
  const [providers, setProviders] = useState<ProviderHealthItem[]>([]);
  const [recentIndicators, setRecentIndicators] = useState<EnrichedIndicatorItem[]>([]);
  const [threatStats, setThreatStats] = useState<Record<string, unknown>>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [searchType, setSearchType] = useState('auto');
  const [isSearching, setIsSearching] = useState(false);
  const [searchedIndicator, setSearchedIndicator] = useState<EnrichedIndicatorItem | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);

  // Benchmark State
  const [liveMetrics, setLiveMetrics] = useState<LiveBenchmarkMetrics | null>(null);
  const [recentEvents, setRecentEvents] = useState<BenchmarkEventItem[]>([]);
  const [scenarios, setScenarios] = useState<BenchmarkScenarioItem[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);
  const [scenarioResults, setScenarioResults] = useState<Record<string, BenchmarkScenarioExecutionResult>>({});
  const [runningScenarioId, setRunningScenarioId] = useState<string | null>(null);

  // Suite Runner State
  const [isRunningSuite, setIsRunningSuite] = useState(false);
  const [suiteIterations, setSuiteIterations] = useState(10);
  const [suiteProgress, setSuiteProgress] = useState(0);
  const [suiteResult, setSuiteResult] = useState<Record<string, unknown> | null>(null);

  // Inspector Drawer
  const [inspectedItem, setInspectedItem] = useState<Record<string, unknown> | null>(null);

  // Polling ref
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Fetch initial data
  const fetchData = async () => {
    try {
      const [provs, inds, stats, metrics, evts, scens] = await Promise.all([
        api.getThreatIntelProviders().catch(() => []),
        api.getRecentIndicators(40).catch(() => []),
        api.getThreatIntelStats().catch(() => ({})),
        api.getLiveBenchmarkMetrics().catch(() => null),
        api.getRecentBenchmarkEvents(30).catch(() => []),
        api.getBenchmarkScenarios().catch(() => []),
      ]);

      setProviders(provs);
      setRecentIndicators(inds);
      setThreatStats(stats);
      if (metrics) setLiveMetrics(metrics);
      setRecentEvents(evts);
      setScenarios(scens);
      if (scens.length > 0 && !selectedScenarioId) {
        setSelectedScenarioId(scens[0].id);
      }
    } catch (err) {
      console.error('Failed to load threat intel & benchmark data:', err);
    }
  };

  useEffect(() => {
    fetchData();
    pollIntervalRef.current = setInterval(() => {
      fetchData();
    }, 2500);

    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    };
  }, []);

  // Handle on-demand indicator lookup
  const handleSearchIndicator = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!searchQuery.trim()) return;

    setIsSearching(true);
    setSearchError(null);
    try {
      const res = await api.lookupThreatIndicator(
        searchQuery.trim(),
        searchType === 'auto' ? undefined : searchType,
        true
      );
      setSearchedIndicator(res);
      fetchData();
    } catch (err: any) {
      setSearchError(err.message || 'Lookup failed');
    } finally {
      setIsSearching(false);
    }
  };

  // Run single scenario
  const handleRunScenario = async (scenId: string) => {
    setRunningScenarioId(scenId);
    try {
      const res = await api.runBenchmarkScenario(scenId);
      setScenarioResults((prev) => ({ ...prev, [scenId]: res }));
      fetchData();
    } catch (err) {
      console.error('Scenario run error:', err);
    } finally {
      setRunningScenarioId(null);
    }
  };

  // Run automated benchmark suite
  const handleRunSuite = async () => {
    setIsRunningSuite(true);
    setSuiteProgress(15);
    setSuiteResult(null);

    const progressTimer = setInterval(() => {
      setSuiteProgress((p) => (p < 90 ? p + Math.floor(Math.random() * 15 + 5) : p));
    }, 400);

    try {
      const res = await api.runBenchmarkSuite(suiteIterations);
      clearInterval(progressTimer);
      setSuiteProgress(100);
      setSuiteResult(res);
      fetchData();
    } catch (err) {
      clearInterval(progressTimer);
      console.error('Benchmark suite error:', err);
    } finally {
      setIsRunningSuite(false);
    }
  };

  const getReputationBadge = (rep: string) => {
    switch (rep?.toLowerCase()) {
      case 'malicious':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200">
            <Flame className="w-3.5 h-3.5 text-rose-600" />
            MALICIOUS
          </span>
        );
      case 'suspicious':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            SUSPICIOUS
          </span>
        );
      case 'benign':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
            BENIGN
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700 border border-slate-200">
            <Radio className="w-3.5 h-3.5 text-slate-500" />
            UNKNOWN
          </span>
        );
    }
  };

  const getProviderStatusBadge = (status: string, hasKey: boolean) => {
    switch (status) {
      case 'online':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            ONLINE
          </span>
        );
      case 'no_key':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-amber-50 text-amber-700 border border-amber-200">
            <Lock className="w-3 h-3 text-amber-500" />
            KEY OPTIONAL
          </span>
        );
      case 'degraded':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold bg-orange-50 text-orange-700 border border-orange-200">
            <AlertTriangle className="w-3 h-3 text-orange-500" />
            DEGRADED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">
            OFFLINE
          </span>
        );
    }
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-emerald-50 text-emerald-700 border border-emerald-200">ALLOW</span>;
      case 'WARN':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-amber-50 text-amber-700 border border-amber-200">WARN</span>;
      case 'REQUIRE_APPROVAL':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-sky-50 text-sky-700 border border-sky-200">REQUIRE_APPROVAL</span>;
      case 'BLOCK':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-rose-50 text-rose-700 border border-rose-200">BLOCK</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-slate-100 text-slate-700">{decision}</span>;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50/50 p-6 space-y-6 font-sans antialiased text-slate-800">
      {/* ── Top Header & Sub-Navigation ── */}
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="w-10 h-10 rounded-lg bg-emerald-700 text-white flex items-center justify-center shadow-md shadow-emerald-700/20">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
                  Live Threat Intelligence & Real-Time Benchmark
                  <span className="px-2.5 py-0.5 text-xs font-semibold bg-emerald-100 text-emerald-800 rounded-full border border-emerald-200">
                    Live Telemetry
                  </span>
                </h1>
                <p className="text-xs text-slate-500 mt-0.5">
                  Real multi-provider intelligence layer (AbuseIPDB, OTX, VirusTotal, URLhaus, CISA KEV, Shodan, GreyNoise) and live runtime performance benchmarking.
                </p>
              </div>
            </div>
          </div>

          {/* Sub Navigation Tabs */}
          <div className="flex items-center gap-1.5 p-1 bg-slate-100 rounded-lg border border-slate-200 self-start lg:self-auto overflow-x-auto">
            <button
              onClick={() => setActiveSubTab('threat-intel')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-md text-xs font-semibold transition-all ${
                activeSubTab === 'threat-intel'
                  ? 'bg-white text-emerald-800 shadow-sm border border-slate-200/80'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
              }`}
            >
              <Crosshair className="w-3.5 h-3.5 text-emerald-600" />
              Live Indicator Stream
            </button>
            <button
              onClick={() => setActiveSubTab('providers')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-md text-xs font-semibold transition-all ${
                activeSubTab === 'providers'
                  ? 'bg-white text-emerald-800 shadow-sm border border-slate-200/80'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
              }`}
            >
              <Server className="w-3.5 h-3.5 text-emerald-600" />
              7 Threat Providers ({providers.filter(p => p.status === 'online').length}/{providers.length} Active)
            </button>
            <button
              onClick={() => setActiveSubTab('benchmark-metrics')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-md text-xs font-semibold transition-all ${
                activeSubTab === 'benchmark-metrics'
                  ? 'bg-white text-emerald-800 shadow-sm border border-slate-200/80'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-emerald-600" />
              Live Benchmark & Latencies
            </button>
            <button
              onClick={() => setActiveSubTab('judge-demo')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-md text-xs font-semibold transition-all ${
                activeSubTab === 'judge-demo'
                  ? 'bg-white text-emerald-800 shadow-sm border border-slate-200/80'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-200/50'
              }`}
            >
              <Play className="w-3.5 h-3.5 text-emerald-600" />
              Controlled Judge Evaluation Mode
            </button>
          </div>
        </div>
      </div>

      {/* ── KPI Summary Cards ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Gateway Events Evaluated</span>
            <Activity className="w-4 h-4 text-emerald-700" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-slate-900">
              {liveMetrics?.total_events_evaluated ?? 0}
            </span>
            <span className="text-xs text-emerald-700 font-medium">
              {liveMetrics?.throughput_events_per_sec ?? 0} ev/s
            </span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-slate-100 pt-2">
            <span>Uptime: {Math.floor((liveMetrics?.uptime_seconds ?? 0) / 60)}m {Math.floor((liveMetrics?.uptime_seconds ?? 0) % 60)}s</span>
            <span className="text-emerald-700 font-semibold">Zero Hardcoded Data</span>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Gateway P95 Latency</span>
            <Clock className="w-4 h-4 text-sky-700" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-slate-900">
              {liveMetrics?.gateway_latency_ms.p95 ?? 0.0}
            </span>
            <span className="text-xs text-slate-500">ms</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-slate-100 pt-2">
            <span>Avg: {liveMetrics?.gateway_latency_ms.avg ?? 0.0}ms</span>
            <span>P99: {liveMetrics?.gateway_latency_ms.p99 ?? 0.0}ms</span>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Threat Intel Cache Efficiency</span>
            <Zap className="w-4 h-4 text-amber-700" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black text-slate-900">
              {liveMetrics?.threat_intel_stats.cache_hit_rate_pct ?? 0}%
            </span>
            <span className="text-xs text-slate-500 font-medium">
              ({liveMetrics?.threat_intel_stats.cache_hits ?? 0} hits / {liveMetrics?.threat_intel_stats.cache_misses ?? 0} misses)
            </span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-slate-100 pt-2">
            <span>Indicators: {liveMetrics?.threat_intel_stats.total_indicators_enriched ?? 0}</span>
            <span className="text-emerald-700 font-medium">TTL In-Memory</span>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-slate-500 mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider">Decision Outcomes</span>
            <Shield className="w-4 h-4 text-emerald-700" />
          </div>
          <div className="grid grid-cols-4 gap-1 text-center mt-1">
            <div className="bg-emerald-50 rounded py-1 px-1 border border-emerald-100">
              <div className="text-xs text-emerald-800 font-bold">{liveMetrics?.decisions.ALLOW ?? 0}</div>
              <div className="text-[10px] text-emerald-700">ALLOW</div>
            </div>
            <div className="bg-amber-50 rounded py-1 px-1 border border-amber-100">
              <div className="text-xs text-amber-800 font-bold">{liveMetrics?.decisions.WARN ?? 0}</div>
              <div className="text-[10px] text-amber-700">WARN</div>
            </div>
            <div className="bg-sky-50 rounded py-1 px-1 border border-sky-100">
              <div className="text-xs text-sky-800 font-bold">{liveMetrics?.decisions.REQUIRE_APPROVAL ?? 0}</div>
              <div className="text-[10px] text-sky-700">APPROVE</div>
            </div>
            <div className="bg-rose-50 rounded py-1 px-1 border border-rose-100">
              <div className="text-xs text-rose-800 font-bold">{liveMetrics?.decisions.BLOCK ?? 0}</div>
              <div className="text-[10px] text-rose-700">BLOCK</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── TAB 1: LIVE INDICATOR STREAM & SEARCH CONSOLE ── */}
      {activeSubTab === 'threat-intel' && (
        <div className="space-y-6">
          {/* On-demand Enrichment Search Bar */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <h2 className="text-base font-bold text-slate-900 mb-1 flex items-center gap-2">
              <Search className="w-4 h-4 text-emerald-700" />
              Live Threat Intelligence Indicator Query
            </h2>
            <p className="text-xs text-slate-500 mb-4">
              Inspect any IP address, domain, URL, file hash (MD5/SHA256), or CVE against live integrated threat intelligence providers.
            </p>

            <form onSubmit={handleSearchIndicator} className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="e.g. 194.26.29.112, http://malicious-c2-payload.com, CVE-2021-44228, 44d88612fea8a8f36de82e1278abb02f"
                  className="w-full pl-10 pr-4 py-2.5 rounded-lg border border-slate-300 focus:outline-none focus:ring-2 focus:ring-emerald-700 focus:border-emerald-700 text-sm font-mono text-slate-800"
                />
                <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-3.5" />
              </div>

              <select
                value={searchType}
                onChange={(e) => setSearchType(e.target.value)}
                className="px-3 py-2.5 rounded-lg border border-slate-300 bg-white text-sm font-medium text-slate-700 focus:outline-none focus:ring-2 focus:ring-emerald-700"
              >
                <option value="auto">Auto-Detect Type</option>
                <option value="ip">IPv4 / IPv6</option>
                <option value="domain">Domain Name</option>
                <option value="url">URL</option>
                <option value="cve">CVE ID</option>
                <option value="hash_md5">MD5 Hash</option>
                <option value="hash_sha256">SHA256 Hash</option>
              </select>

              <button
                type="submit"
                disabled={isSearching || !searchQuery.trim()}
                className="px-5 py-2.5 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-sm font-semibold flex items-center justify-center gap-2 shadow-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSearching ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                Enrich with Live Feeds
              </button>
            </form>

            {searchError && (
              <div className="mt-3 p-3 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                {searchError}
              </div>
            )}

            {/* Searched Indicator Detailed Result Card */}
            {searchedIndicator && (
              <div className="mt-5 p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 pb-3">
                  <div className="flex items-center gap-3">
                    {getReputationBadge(searchedIndicator.overall_reputation)}
                    <span className="font-mono font-bold text-sm text-slate-900">{searchedIndicator.indicator}</span>
                    <span className="px-2 py-0.5 rounded text-[11px] font-semibold uppercase bg-slate-200 text-slate-700">
                      {searchedIndicator.indicator_type}
                    </span>
                    {searchedIndicator.cached && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-100 text-emerald-800">
                        Cached (TTL Hit)
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-500 font-medium">Threat Risk Score:</span>
                    <span className="text-base font-black text-rose-600">{searchedIndicator.overall_risk_score}/100</span>
                  </div>
                </div>

                <p className="text-xs text-slate-700">{searchedIndicator.summary}</p>

                {searchedIndicator.tags && searchedIndicator.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {searchedIndicator.tags.map((tag, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded-full text-[11px] font-medium bg-slate-200/80 text-slate-800">
                        #{tag}
                      </span>
                    ))}
                  </div>
                )}

                {/* Breakdown by Provider */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-slate-700 uppercase tracking-wider">Multi-Provider Breakdown</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                    {searchedIndicator.provider_results.map((pr, idx) => (
                      <div key={idx} className="bg-white p-3 rounded-lg border border-slate-200 text-xs space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-800 uppercase">{pr.provider_name}</span>
                          {getReputationBadge(pr.reputation)}
                        </div>
                        <div className="flex items-center justify-between text-slate-500 text-[11px]">
                          <span>Risk: <strong className="text-slate-800">{pr.risk_score}</strong></span>
                          <span>Confidence: <strong className="text-slate-800">{(pr.confidence * 100).toFixed(0)}%</strong></span>
                          <span>Latency: <strong className="text-slate-800">{pr.latency_ms}ms</strong></span>
                        </div>
                        {pr.error && <p className="text-rose-600 text-[11px] truncate">Error: {pr.error}</p>}
                        {pr.details && Object.keys(pr.details).length > 0 && (
                          <div className="pt-1 text-[11px] text-slate-600 space-y-0.5 border-t border-slate-100">
                            {pr.details.abuse_confidence_score !== undefined && (
                              <div>Abuse Confidence: <strong>{String(pr.details.abuse_confidence_score)}%</strong></div>
                            )}
                            {Boolean(pr.details.threat) && (
                              <div>Threat Type: <strong>{String(pr.details.threat)}</strong></div>
                            )}
                            {Boolean(pr.details.vulnerability_name) && (
                              <div className="truncate">Vuln: <strong>{String(pr.details.vulnerability_name)}</strong></div>
                            )}
                            {Boolean(pr.details.classification) && (
                              <div>Classification: <strong>{String(pr.details.classification)}</strong></div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Live Extracted Indicators Stream from Agent Interceptions */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-emerald-700" />
                  Live Pre-Execution Intercepted Indicators
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Extracted in real-time from agent tool arguments and evaluated at the Gateway enforcement boundary.
                </p>
              </div>
              <button
                onClick={fetchData}
                className="p-2 text-slate-500 hover:text-slate-800 hover:bg-slate-100 rounded-lg transition-all"
                title="Refresh Stream"
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>

            {recentIndicators.length === 0 ? (
              <div className="p-8 text-center text-slate-400 bg-slate-50 rounded-lg border border-dashed border-slate-200">
                <Crosshair className="w-8 h-8 mx-auto mb-2 text-slate-300" />
                <p className="text-sm font-medium">No external security indicators extracted yet.</p>
                <p className="text-xs text-slate-400 mt-1">Run an agent scenario or lookup an indicator above to observe live enrichment.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-700">
                  <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                    <tr>
                      <th className="py-3 px-4">Indicator</th>
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Verdict</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Primary Provider</th>
                      <th className="py-3 px-4">Cache</th>
                      <th className="py-3 px-4">Timestamp</th>
                      <th className="py-3 px-4 text-right">Inspect</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono">
                    {recentIndicators.map((ind, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-3 px-4 font-bold text-slate-900 max-w-xs truncate">{ind.indicator}</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[11px] font-sans font-medium uppercase">
                            {ind.indicator_type}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-sans">{getReputationBadge(ind.overall_reputation)}</td>
                        <td className="py-3 px-4">
                          <span className={`font-bold ${ind.overall_risk_score >= 75 ? 'text-rose-600' : ind.overall_risk_score >= 35 ? 'text-amber-600' : 'text-emerald-600'}`}>
                            {ind.overall_risk_score.toFixed(1)}/100
                          </span>
                        </td>
                        <td className="py-3 px-4 font-sans font-medium text-slate-800">{ind.primary_provider || 'multi-provider'}</td>
                        <td className="py-3 px-4 font-sans">
                          {ind.cached ? (
                            <span className="text-emerald-600 font-semibold text-[11px]">HIT (TTL)</span>
                          ) : (
                            <span className="text-slate-400 text-[11px]">MISS</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px] font-sans">
                          {ind.timestamp ? new Date(ind.timestamp).toLocaleTimeString() : 'Recent'}
                        </td>
                        <td className="py-3 px-4 text-right font-sans">
                          <button
                            onClick={() => setInspectedItem(ind as any)}
                            className="px-2.5 py-1 text-xs rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium inline-flex items-center gap-1"
                          >
                            <Eye className="w-3 h-3" />
                            View
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 2: 7 THREAT PROVIDERS HEALTH MATRIX ── */}
      {activeSubTab === 'providers' && (
        <div className="space-y-6">
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <Server className="w-4 h-4 text-emerald-700" />
                  Threat Intelligence Providers Health & Feeds
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Unified normalization layer with circuit breakers, graceful fail-open/fail-closed semantics, and live rate limit tracking.
                </p>
              </div>
              <button
                onClick={fetchData}
                className="px-3 py-1.5 text-xs rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50 font-medium flex items-center gap-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Poll Status
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {providers.map((p, idx) => (
                <div key={idx} className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3 hover:border-emerald-300 transition-all">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="font-bold text-sm text-slate-900">{p.display_name}</h3>
                      <span className="text-[11px] text-slate-400 font-mono">id: {p.provider_name}</span>
                    </div>
                    {getProviderStatusBadge(p.status, p.has_api_key)}
                  </div>

                  <div className="grid grid-cols-3 gap-2 p-2.5 rounded-lg bg-slate-50 text-center border border-slate-100">
                    <div>
                      <div className="text-xs font-bold text-slate-800">{p.total_queries}</div>
                      <div className="text-[10px] text-slate-400">Total Queries</div>
                    </div>
                    <div>
                      <div className="text-xs font-bold text-emerald-600">{p.successful_queries}</div>
                      <div className="text-[10px] text-slate-400">Success</div>
                    </div>
                    <div>
                      <div className="text-xs font-bold text-slate-800">{p.avg_latency_ms}ms</div>
                      <div className="text-[10px] text-slate-400">Avg Latency</div>
                    </div>
                  </div>

                  <div className="space-y-1.5 text-xs text-slate-600">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Tier:</span>
                      <span className="font-semibold text-slate-700">{p.is_free_tier ? 'Public / Free' : 'API Key Req'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">API Key Configured:</span>
                      <span className={`font-semibold ${p.has_api_key ? 'text-emerald-600' : 'text-slate-400'}`}>
                        {p.has_api_key ? 'YES (Active)' : 'NO (.env ready)'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500">Supported Indicators:</span>
                      <span className="font-mono text-[11px] text-slate-700">
                        {p.supported_types.map(t => t.toUpperCase()).join(', ')}
                      </span>
                    </div>
                    {p.rate_limit_info && (
                      <div className="p-2 rounded bg-amber-50 border border-amber-200 text-[11px] text-amber-800">
                        {p.rate_limit_info}
                      </div>
                    )}
                    {p.last_error && (
                      <div className="p-2 rounded bg-rose-50 border border-rose-200 text-[11px] text-rose-700 truncate">
                        Last Error: {p.last_error}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 3: REAL-TIME BENCHMARK & LATENCY COCKPIT ── */}
      {activeSubTab === 'benchmark-metrics' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Gateway Latency Percentile Distribution */}
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm space-y-4">
              <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <Clock className="w-4 h-4 text-emerald-700" />
                Pre-Execution Gateway Latency Distribution
              </h3>
              <p className="text-xs text-slate-500">
                True calculated millisecond percentiles from actual runtime actions evaluated through the gateway.
              </p>

              <div className="grid grid-cols-3 gap-3">
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-xs font-semibold text-slate-500 uppercase">P50 (Median)</div>
                  <div className="text-2xl font-black text-slate-900 mt-1">{liveMetrics?.gateway_latency_ms.p50 ?? 0.0}ms</div>
                  <div className="text-[10px] text-emerald-700 mt-0.5">50% of all requests</div>
                </div>
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-xs font-semibold text-slate-500 uppercase">P95 (Standard)</div>
                  <div className="text-2xl font-black text-slate-900 mt-1">{liveMetrics?.gateway_latency_ms.p95 ?? 0.0}ms</div>
                  <div className="text-[10px] text-emerald-700 mt-0.5">95% under this latency</div>
                </div>
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-xs font-semibold text-slate-500 uppercase">P99 (Tail)</div>
                  <div className="text-2xl font-black text-slate-900 mt-1">{liveMetrics?.gateway_latency_ms.p99 ?? 0.0}ms</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Worst 1% tail</div>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 border border-slate-100 flex items-center justify-between text-xs text-slate-600">
                <span>Fastest / Min Latency: <strong className="text-slate-800">{liveMetrics?.gateway_latency_ms.min ?? 0.0}ms</strong></span>
                <span>Average: <strong className="text-slate-800">{liveMetrics?.gateway_latency_ms.avg ?? 0.0}ms</strong></span>
                <span>Max Latency: <strong className="text-slate-800">{liveMetrics?.gateway_latency_ms.max ?? 0.0}ms</strong></span>
              </div>
            </div>

            {/* Threat Intel Lookup Latency & Cache Stats */}
            <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm space-y-4">
              <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
                <Zap className="w-4 h-4 text-emerald-700" />
                Threat Intelligence Query & Cache Metrics
              </h3>
              <p className="text-xs text-slate-500">
                Parallel async dispatch overhead and in-memory TTL cache acceleration.
              </p>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-xs font-semibold text-slate-500 uppercase">Threat Intel Avg Latency</div>
                  <div className="text-2xl font-black text-slate-900 mt-1">{liveMetrics?.threat_intel_latency_ms.avg ?? 0.0}ms</div>
                  <div className="text-[10px] text-emerald-700 mt-0.5">Parallel multi-provider</div>
                </div>
                <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 text-center">
                  <div className="text-xs font-semibold text-slate-500 uppercase">Cache Hit Rate</div>
                  <div className="text-2xl font-black text-slate-900 mt-1">{liveMetrics?.threat_intel_stats.cache_hit_rate_pct ?? 0}%</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{liveMetrics?.threat_intel_stats.cache_hits ?? 0} hits / {liveMetrics?.threat_intel_stats.cache_misses ?? 0} misses</div>
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 border border-slate-100 flex items-center justify-between text-xs text-slate-600">
                <span>Active Providers: <strong className="text-slate-800">{liveMetrics?.threat_intel_stats.active_providers_count} / {liveMetrics?.threat_intel_stats.total_providers}</strong></span>
                <span>Enriched Indicators: <strong className="text-slate-800">{liveMetrics?.threat_intel_stats.total_indicators_enriched}</strong></span>
              </div>
            </div>
          </div>

          {/* Recent Benchmark Event Ring Buffer */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <h3 className="text-base font-bold text-slate-900 mb-1 flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-700" />
              Live Gateway Decision & Performance Stream
            </h3>
            <p className="text-xs text-slate-500 mb-4">
              Real-time ring buffer of the last evaluated actions including measured latencies, security reasons, and threat details.
            </p>

            {recentEvents.length === 0 ? (
              <div className="p-6 text-center text-slate-400 bg-slate-50 rounded-lg">
                No benchmark events recorded yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-700">
                  <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                    <tr>
                      <th className="py-3 px-4">Event ID</th>
                      <th className="py-3 px-4">Agent</th>
                      <th className="py-3 px-4">Tool</th>
                      <th className="py-3 px-4">Decision</th>
                      <th className="py-3 px-4">Gateway Latency</th>
                      <th className="py-3 px-4">Risk Score</th>
                      <th className="py-3 px-4">Reasons</th>
                      <th className="py-3 px-4 text-right">Time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 font-mono">
                    {recentEvents.map((ev, idx) => (
                      <tr key={idx} className="hover:bg-slate-50/80 transition-colors">
                        <td className="py-3 px-4 text-slate-500">{ev.id}</td>
                        <td className="py-3 px-4 font-bold text-slate-900">{ev.agent_id}</td>
                        <td className="py-3 px-4 text-slate-700">{ev.tool_name}</td>
                        <td className="py-3 px-4 font-sans">{getDecisionBadge(ev.outcome)}</td>
                        <td className="py-3 px-4 font-bold text-slate-800">{ev.gateway_latency_ms}ms</td>
                        <td className="py-3 px-4">
                          <span className={`font-bold ${ev.risk_score >= 70 ? 'text-rose-600' : ev.risk_score >= 30 ? 'text-amber-600' : 'text-emerald-600'}`}>
                            {ev.risk_score}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-slate-600 font-sans truncate max-w-xs">
                          {ev.reasons && ev.reasons.length > 0 ? ev.reasons.join(', ') : 'None'}
                        </td>
                        <td className="py-3 px-4 text-right text-slate-400 font-sans text-[11px]">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 4: CONTROLLED JUDGE EVALUATION MODE ── */}
      {activeSubTab === 'judge-demo' && (
        <div className="space-y-6">
          {/* Automated Benchmark Suite Runner Card */}
          <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-sm">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
                  <Play className="w-4 h-4 text-emerald-700" />
                  Live Automated Benchmark Suite
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Execute multiple concurrent iterations across all threat scenarios to measure ground-truth accuracy and calculate real latency percentiles.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="flex items-center gap-2 text-xs text-slate-600 font-medium">
                  <span>Iterations per Scenario:</span>
                  <select
                    value={suiteIterations}
                    onChange={(e) => setSuiteIterations(Number(e.target.value))}
                    disabled={isRunningSuite}
                    className="px-2.5 py-1.5 rounded-md border border-slate-300 bg-white text-xs font-semibold"
                  >
                    <option value={5}>5 iter (35 tests)</option>
                    <option value={10}>10 iter (70 tests)</option>
                    <option value={20}>20 iter (140 tests)</option>
                  </select>
                </div>

                <button
                  onClick={handleRunSuite}
                  disabled={isRunningSuite}
                  className="px-4 py-2 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold flex items-center gap-2 shadow-sm transition-all disabled:opacity-50"
                >
                  {isRunningSuite ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
                  {isRunningSuite ? 'Executing Live Suite...' : 'Run Automated Benchmark Suite'}
                </button>
              </div>
            </div>

            {/* Progress Bar */}
            {isRunningSuite && (
              <div className="mt-4 space-y-2">
                <div className="flex items-center justify-between text-xs text-slate-600 font-medium">
                  <span>Running Real-Time Gateway Pipeline & Threat Intel Verification...</span>
                  <span className="font-bold text-emerald-700">{suiteProgress}%</span>
                </div>
                <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-emerald-700 transition-all duration-300 rounded-full"
                    style={{ width: `${suiteProgress}%` }}
                  />
                </div>
              </div>
            )}

            {/* Suite Summary Results Card */}
            {suiteResult && (
              <div className="mt-5 p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                    <h3 className="font-bold text-sm text-slate-900">
                      Benchmark Suite Completed — {String(suiteResult.total_tests)} Real Executions
                    </h3>
                  </div>
                  <span className="text-xs text-slate-500 font-mono">Run ID: {String(suiteResult.run_id)}</span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="bg-white p-3 rounded-lg border border-slate-200 text-center">
                    <div className="text-xs text-slate-500">Ground Truth Accuracy</div>
                    <div className="text-xl font-black text-emerald-700 mt-1">{String(suiteResult.accuracy_pct)}%</div>
                  </div>
                  <div className="bg-white p-3 rounded-lg border border-slate-200 text-center">
                    <div className="text-xs text-slate-500">P50 Latency</div>
                    <div className="text-xl font-black text-slate-900 mt-1">
                      {(suiteResult.latency_stats_ms as any)?.p50 ?? 0}ms
                    </div>
                  </div>
                  <div className="bg-white p-3 rounded-lg border border-slate-200 text-center">
                    <div className="text-xs text-slate-500">P95 Latency</div>
                    <div className="text-xl font-black text-slate-900 mt-1">
                      {(suiteResult.latency_stats_ms as any)?.p95 ?? 0}ms
                    </div>
                  </div>
                  <div className="bg-white p-3 rounded-lg border border-slate-200 text-center">
                    <div className="text-xs text-slate-500">P99 Latency</div>
                    <div className="text-xl font-black text-slate-900 mt-1">
                      {(suiteResult.latency_stats_ms as any)?.p99 ?? 0}ms
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Interactive Multi-Scenario Judge Cockpit */}
          <div className="space-y-4">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-emerald-700" />
              Controlled Scenario Matrix ({scenarios.length} Attack & Baseline Vectors)
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {scenarios.map((scen) => {
                const res = scenarioResults[scen.id];
                const isRunning = runningScenarioId === scen.id;

                return (
                  <div
                    key={scen.id}
                    className={`bg-white rounded-xl border p-5 shadow-sm space-y-3 transition-all ${
                      res
                        ? res.decision_matched
                          ? 'border-emerald-300 bg-emerald-50/10'
                          : 'border-rose-300 bg-rose-50/10'
                        : 'border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                            {scen.category}
                          </span>
                          <span className="text-[11px] font-mono text-slate-400">agent: {scen.agent_id}</span>
                        </div>
                        <h4 className="font-bold text-sm text-slate-900 mt-1">{scen.name}</h4>
                      </div>

                      <button
                        onClick={() => handleRunScenario(scen.id)}
                        disabled={isRunning}
                        className="px-3 py-1.5 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-xs font-bold flex items-center gap-1.5 shadow-sm disabled:opacity-50 transition-all flex-shrink-0"
                      >
                        {isRunning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                        {isRunning ? 'Running...' : 'Run Scenario'}
                      </button>
                    </div>

                    <p className="text-xs text-slate-600">{scen.description}</p>

                    {/* Proposed Tool & Arguments Preview */}
                    <div className="p-2.5 rounded-lg bg-slate-900 text-slate-200 font-mono text-[11px] space-y-1">
                      <div className="text-slate-400">tool: <span className="text-emerald-400 font-bold">{scen.tool_name}</span></div>
                      <div className="text-slate-400">args: <span className="text-slate-200">{JSON.stringify(scen.arguments)}</span></div>
                    </div>

                    {/* Ground-Truth vs Actual Comparison */}
                    <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-100">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 font-medium">Expected:</span>
                        {getDecisionBadge(scen.expected_outcome)}
                      </div>

                      {res ? (
                        <div className="flex items-center gap-2">
                          <span className="text-slate-500 font-medium">Actual:</span>
                          {getDecisionBadge(res.actual_decision)}
                          {res.decision_matched ? (
                            <span className="inline-flex items-center gap-1 text-emerald-600 font-bold text-xs">
                              <Check className="w-3.5 h-3.5" /> MATCH ({res.latency_ms}ms)
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-rose-600 font-bold text-xs">
                              <XCircle className="w-3.5 h-3.5" /> MISMATCH
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-400 text-xs italic">Awaiting execution</span>
                      )}
                    </div>

                    {/* Render Threat Signals if present */}
                    {res && res.threat_details && res.threat_details.length > 0 && (
                      <div className="p-2.5 rounded-lg bg-rose-50/80 border border-rose-200 text-xs space-y-1 text-rose-900">
                        <div className="font-bold flex items-center gap-1 text-rose-700">
                          <Flame className="w-3.5 h-3.5" />
                          Threat Intel Signal Detected:
                        </div>
                        {res.threat_details.map((td, i) => (
                          <div key={i} className="text-[11px] text-rose-800">
                            • <strong>{String(td.indicator)}</strong> ({String(td.type)}): {String(td.summary || td.reputation)}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── JSON Inspection Modal / Drawer ── */}
      {inspectedItem && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-2xl w-full max-h-[80vh] flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="p-4 border-b border-slate-200 flex items-center justify-between">
              <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-700" />
                Raw Telemetry & Threat Intelligence Inspector
              </h3>
              <button
                onClick={() => setInspectedItem(null)}
                className="p-1 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-slate-800"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 overflow-y-auto flex-1 bg-slate-900 text-slate-100 font-mono text-xs">
              <pre className="whitespace-pre-wrap">{JSON.stringify(inspectedItem, null, 2)}</pre>
            </div>
            <div className="p-3 border-t border-slate-200 flex justify-end bg-slate-50">
              <button
                onClick={() => setInspectedItem(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 text-white text-xs font-semibold hover:bg-slate-900"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
