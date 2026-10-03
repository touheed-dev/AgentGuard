import React, { useState, useEffect } from 'react';
import {
  FileText,
  Shield,
  ShieldAlert,
  Database,
  Terminal,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Flame,
  Layers,
  ArrowRight,
  Cpu,
  Info,
  ExternalLink,
  Eye,
} from 'lucide-react';
import { api } from '../api';
import { DemoEnvironmentData, DemoScenarioResult, DemoScenarioInfo } from '../types';

interface DemoWorkspaceViewProps {
  onRefreshAll?: () => void;
  onNavigateToTrace?: (traceId: string) => void;
}

export const DemoWorkspaceView: React.FC<DemoWorkspaceViewProps> = ({
  onRefreshAll,
  onNavigateToTrace,
}) => {
  const [envData, setEnvData] = useState<DemoEnvironmentData | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('legitimate_research');
  const [isRunningScenario, setIsRunningScenario] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);
  const [lastScenarioResult, setLastScenarioResult] = useState<DemoScenarioResult | null>(null);
  const [selectedResource, setSelectedResource] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const fetchEnvironment = async () => {
    try {
      const data = await api.getDemoEnvironment();
      setEnvData(data);
      setErrorMsg(null);
    } catch (err: any) {
      console.error('Failed to load demo environment:', err);
      setErrorMsg(err?.message || 'Failed to connect to gateway');
    }
  };

  useEffect(() => {
    fetchEnvironment();
  }, []);

  const handleRunScenario = async () => {
    setIsRunningScenario(true);
    setErrorMsg(null);
    try {
      const result = await api.runDemoScenario(selectedScenarioId);
      setLastScenarioResult(result);
      await fetchEnvironment();
      if (onRefreshAll) onRefreshAll();
    } catch (err: any) {
      console.error('Error running scenario:', err);
      setErrorMsg(err?.message || 'Scenario execution failed');
    } finally {
      setIsRunningScenario(false);
    }
  };

  const handleReset = async () => {
    setIsResetting(true);
    setErrorMsg(null);
    try {
      await api.resetDemo();
      setLastScenarioResult(null);
      await fetchEnvironment();
      if (onRefreshAll) onRefreshAll();
    } catch (err: any) {
      console.error('Error resetting demo:', err);
      setErrorMsg(err?.message || 'Reset failed');
    } finally {
      setIsResetting(false);
    }
  };

  const activeScenario = envData?.scenarios.find((s) => s.id === selectedScenarioId);

  return (
    <div className="space-y-6 max-w-screen-2xl mx-auto pb-12">
      {/* ── Top Header Banner ── */}
      <div
        className="rounded-2xl p-6 border transition-all"
        style={{
          background: 'linear-gradient(135deg, #FBF8F3 0%, #F5EFE6 100%)',
          borderColor: '#E2D9CC',
          boxShadow: '0 4px 20px -2px rgba(100, 85, 70, 0.06)',
        }}
      >
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div
                className="w-9 h-9 rounded-xl flex items-center justify-center border shadow-sm"
                style={{ background: '#1E1B18', borderColor: '#332E27' }}
              >
                <Layers className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h1 className="text-xl font-serif font-bold tracking-tight text-stone-900">
                  Demo Environment &amp; Agent Workspace
                </h1>
                <p className="text-xs font-mono text-stone-600">
                  Active Data Resources • Real LLM Autonomous Agent • Deterministic Gateway Enforcement
                </p>
              </div>
            </div>
          </div>

          {/* ── Action Buttons ── */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleReset}
              disabled={isResetting}
              className="px-4 py-2.5 rounded-xl font-mono text-xs font-medium border flex items-center gap-2 transition-all hover:shadow-sm"
              style={{
                background: '#EDE7DC',
                borderColor: '#D8CEBE',
                color: '#44403C',
              }}
            >
              <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-amber-700' : 'text-stone-600'}`} />
              <span>{isResetting ? 'RESETTING...' : 'RESET ENVIRONMENT'}</span>
            </button>

            <button
              onClick={handleRunScenario}
              disabled={isRunningScenario}
              className="px-6 py-2.5 rounded-xl font-mono text-xs font-bold text-white flex items-center gap-2.5 transition-all shadow-md active:scale-95"
              style={{
                background: 'linear-gradient(135deg, #1E1B18 0%, #332E27 100%)',
                border: '1px solid #443D34',
              }}
            >
              <Play className={`w-4 h-4 ${isRunningScenario ? 'animate-pulse text-amber-400' : 'text-amber-400 fill-amber-400'}`} />
              <span>{isRunningScenario ? 'EXECUTING PIPELINE...' : 'RUN LIVE SCENARIO'}</span>
            </button>
          </div>
        </div>

        {/* ── Scenario Selection Strip ── */}
        <div className="mt-6 pt-5 border-t border-stone-300/60">
          <div className="text-[11px] font-mono font-bold uppercase tracking-wider text-stone-600 mb-3 flex items-center justify-between">
            <span>Select Interactive Scenario</span>
            <span className="text-[10px] text-stone-600">Routes through real 20-Stage Security Gateway</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {envData?.scenarios.map((sc) => {
              const isSelected = sc.id === selectedScenarioId;
              let badgeColor = 'bg-emerald-100 text-emerald-800 border-emerald-300';
              if (sc.expected_decision === 'BLOCK') badgeColor = 'bg-rose-100 text-rose-800 border-rose-300';
              if (sc.expected_decision === 'REQUIRE_APPROVAL') badgeColor = 'bg-amber-100 text-amber-800 border-amber-300';
              if (sc.expected_decision === 'BLOCK + QUARANTINE') badgeColor = 'bg-purple-100 text-purple-800 border-purple-300';

              return (
                <div
                  key={sc.id}
                  onClick={() => setSelectedScenarioId(sc.id)}
                  className={`cursor-pointer rounded-xl p-3.5 border transition-all ${
                    isSelected
                      ? 'ring-2 ring-amber-700/60 shadow-md'
                      : 'hover:border-stone-400 opacity-80 hover:opacity-100'
                  }`}
                  style={{
                    background: isSelected ? '#FFFFFF' : '#F7F3EC',
                    borderColor: isSelected ? '#B45309' : '#DCD4C7',
                  }}
                >
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <span className="font-serif font-bold text-xs text-stone-900 truncate">
                      {sc.name}
                    </span>
                    <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${badgeColor}`}>
                      {sc.expected_decision}
                    </span>
                  </div>
                  <p className="text-[11px] text-stone-600 line-clamp-2 leading-relaxed">
                    {sc.description}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* ── Middle Row: Agent State & Live Execution Outcome ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ── Column 1: Active Agent Card (4 cols) ── */}
        <div
          className="lg:col-span-4 rounded-2xl p-5 border flex flex-col justify-between"
          style={{ background: '#FBF8F3', borderColor: '#E2D9CC' }}
        >
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-stone-200">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-amber-700" />
                <span className="font-mono text-xs font-bold text-stone-900 uppercase tracking-wider">
                  Target AI Agent
                </span>
              </div>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                {envData?.agent.status || 'ACTIVE'}
              </span>
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <div className="text-[10px] font-mono text-stone-600 uppercase">Agent Identity</div>
                <div className="text-sm font-serif font-bold text-stone-900">
                  {envData?.agent.name} ({envData?.agent.agent_id})
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono text-stone-600 uppercase">Assigned Task Scope</div>
                <div className="text-xs font-mono font-medium text-stone-700 bg-stone-100 p-2 rounded-lg border border-stone-200">
                  task_id: "{envData?.agent.task_id}" (Company Research)
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono text-stone-600 uppercase">Security Epoch / Quarantine Status</div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs font-mono font-bold text-stone-800">
                    Epoch: #{envData?.agent.security_epoch}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-stone-200 text-stone-700">
                    State: {envData?.agent.security_state}
                  </span>
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono text-stone-600 uppercase mb-1.5">Registered Tool Capabilities</div>
                <div className="flex flex-wrap gap-1.5">
                  {envData?.agent.allowed_tools.map((t) => (
                    <span
                      key={t}
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-stone-100 border border-stone-200 text-stone-700"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-3 border-t border-stone-200 text-[10px] font-mono text-stone-600 flex items-center justify-between">
            <span>Execution Invariant: FAIL-CLOSED</span>
            <span className="text-emerald-700 font-bold">ZERO DIRECT ACCESS</span>
          </div>
        </div>

        {/* ── Column 2: Live Execution Outcome / "What Just Happened?" (8 cols) ── */}
        <div
          className="lg:col-span-8 rounded-2xl p-5 border flex flex-col justify-between"
          style={{ background: '#FBF8F3', borderColor: '#E2D9CC' }}
        >
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-stone-200">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-amber-700" />
                <span className="font-mono text-xs font-bold text-stone-900 uppercase tracking-wider">
                  Live Execution Outcome • "What Just Happened?"
                </span>
              </div>
              {lastScenarioResult && (
                <span className="text-[10px] font-mono font-bold text-stone-600">
                  Trace: {lastScenarioResult.trace_id}
                </span>
              )}
            </div>

            {lastScenarioResult ? (
              <div className="mt-4 space-y-4">
                {/* Decision Banner */}
                <div
                  className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    lastScenarioResult.decision === 'ALLOW'
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-950'
                      : lastScenarioResult.decision === 'BLOCK'
                      ? 'bg-rose-50 border-rose-200 text-rose-950'
                      : 'bg-amber-50 border-amber-200 text-amber-950'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-10 h-10 rounded-xl flex items-center justify-center border font-serif font-bold text-lg ${
                        lastScenarioResult.decision === 'ALLOW'
                          ? 'bg-emerald-600 text-white border-emerald-700'
                          : lastScenarioResult.decision === 'BLOCK'
                          ? 'bg-rose-600 text-white border-rose-700'
                          : 'bg-amber-600 text-white border-amber-700'
                      }`}
                    >
                      {lastScenarioResult.decision === 'ALLOW' ? '✓' : lastScenarioResult.decision === 'BLOCK' ? '✗' : '!'}
                    </div>
                    <div>
                      <div className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-75">
                        Gateway Decision Result
                      </div>
                      <div className="text-base font-serif font-bold">
                        {lastScenarioResult.decision}
                        {lastScenarioResult.agent_quarantined && ' (AGENT QUARANTINED)'}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 text-right">
                    <div>
                      <div className="text-[10px] font-mono uppercase text-stone-600">Execution Status</div>
                      <div className="text-xs font-mono font-bold">
                        {lastScenarioResult.execution_status}
                      </div>
                    </div>
                    <div className="ml-3 pl-3 border-l border-stone-300">
                      <div className="text-[10px] font-mono uppercase text-stone-600">Executions</div>
                      <div className="text-sm font-mono font-bold text-stone-900">
                        {lastScenarioResult.executions_count}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Scenario Details Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="p-3 bg-stone-100/80 rounded-xl border border-stone-200">
                    <div className="text-[10px] text-stone-600 uppercase mb-0.5">Invoked Action</div>
                    <div className="font-bold text-stone-900">{lastScenarioResult.tool_name}()</div>
                  </div>
                  <div className="p-3 bg-stone-100/80 rounded-xl border border-stone-200">
                    <div className="text-[10px] text-stone-600 uppercase mb-0.5">Target Resource</div>
                    <div className="font-bold text-stone-900 truncate" title={lastScenarioResult.target_resource}>
                      {lastScenarioResult.target_resource}
                    </div>
                  </div>
                  <div className="p-3 bg-stone-100/80 rounded-xl border border-stone-200">
                    <div className="text-[10px] text-stone-600 uppercase mb-0.5">Reason Code</div>
                    <div className="font-bold text-stone-900">
                      {lastScenarioResult.reasons.join(', ') || 'POLICY_ALLOW'}
                    </div>
                  </div>
                </div>

                {/* Explanation text */}
                <div className="p-3.5 bg-white rounded-xl border border-stone-200 text-xs font-serif text-stone-800 leading-relaxed">
                  <div className="text-[10px] font-mono font-bold uppercase text-stone-600 mb-1">
                    Enforcement Pipeline Rationale:
                  </div>
                  {lastScenarioResult.explanation}
                </div>

                {/* Output preview if allowed */}
                {lastScenarioResult.output_preview && (
                  <div className="p-3 bg-stone-900 text-stone-200 rounded-xl font-mono text-[11px] overflow-hidden">
                    <div className="text-[10px] text-stone-400 uppercase mb-1">Tool Output Payload:</div>
                    <div className="line-clamp-3 text-emerald-400">
                      {lastScenarioResult.output_preview}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="h-56 flex flex-col items-center justify-center text-center p-6 space-y-2">
                <Play className="w-8 h-8 text-amber-700/40" />
                <div className="text-sm font-serif font-bold text-stone-700">
                  Ready to Run Selected Scenario
                </div>
                <p className="text-xs text-stone-600 max-w-md">
                  Select a scenario above (e.g. <strong>Prompt Injection Attack</strong>) and click <strong>"RUN LIVE SCENARIO"</strong> to observe the complete Gateway enforcement cycle.
                </p>
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-stone-200 flex items-center justify-between text-[11px] font-mono text-stone-600">
            <span>Post-Block Executions: <strong>0 (Fail-Closed)</strong></span>
            <span>Deterministic Enforcement Boundary</span>
          </div>
        </div>
      </div>

      {/* ── Bottom Section: Active Resource Explorer (Files & Database) ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* ── Files Explorer (8 cols) ── */}
        <div
          className="lg:col-span-8 rounded-2xl p-5 border"
          style={{ background: '#FBF8F3', borderColor: '#E2D9CC' }}
        >
          <div className="flex items-center justify-between pb-3 border-b border-stone-200 mb-4">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-amber-700" />
              <span className="font-mono text-xs font-bold text-stone-900 uppercase tracking-wider">
                Filesystem Workspace Resources (data/demo/)
              </span>
            </div>
            <span className="text-[10px] font-mono text-stone-600">
              {envData?.resources.length || 0} Managed Resources
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-stone-200 text-stone-600 text-[10px] uppercase">
                  <th className="pb-2">Resource File</th>
                  <th className="pb-2">Classification</th>
                  <th className="pb-2">Gateway Access Policy</th>
                  <th className="pb-2">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-100">
                {envData?.resources.map((res) => {
                  let badge = 'bg-emerald-100 text-emerald-800 border-emerald-200';
                  let icon = <FileText className="w-3.5 h-3.5 text-emerald-700" />;

                  if (res.classification === 'UNTRUSTED') {
                    badge = 'bg-amber-100 text-amber-800 border-amber-200';
                    icon = <AlertTriangle className="w-3.5 h-3.5 text-amber-700" />;
                  } else if (res.classification === 'RESTRICTED') {
                    badge = 'bg-rose-100 text-rose-800 border-rose-200';
                    icon = <Lock className="w-3.5 h-3.5 text-rose-700" />;
                  } else if (res.classification === 'HONEY_ASSET') {
                    badge = 'bg-purple-100 text-purple-800 border-purple-200';
                    icon = <Flame className="w-3.5 h-3.5 text-purple-700" />;
                  }

                  return (
                    <tr key={res.id} className="hover:bg-stone-100/60 transition-colors">
                      <td className="py-2.5 pr-3">
                        <div className="flex items-center gap-2">
                          {icon}
                          <span className="font-bold text-stone-900">{res.name}</span>
                        </div>
                        <div className="text-[10px] text-stone-600 pl-5">{res.description}</div>
                      </td>
                      <td className="py-2.5 pr-3">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold border ${badge}`}>
                          {res.classification}
                        </span>
                      </td>
                      <td className="py-2.5 pr-3 text-stone-700 text-[11px]">
                        {res.access}
                      </td>
                      <td className="py-2.5 text-stone-600 text-[10px]">
                        {res.size_bytes} B
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Database Explorer (4 cols) ── */}
        <div
          className="lg:col-span-4 rounded-2xl p-5 border"
          style={{ background: '#FBF8F3', borderColor: '#E2D9CC' }}
        >
          <div className="flex items-center justify-between pb-3 border-b border-stone-200 mb-4">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-amber-700" />
              <span className="font-mono text-xs font-bold text-stone-900 uppercase tracking-wider">
                Database Tables
              </span>
            </div>
            <span className="text-[10px] font-mono text-stone-600">In-Memory Engine</span>
          </div>

          <div className="space-y-3">
            {envData?.database.map((db) => {
              let badge = 'bg-emerald-100 text-emerald-800';
              if (db.classification === 'RESTRICTED') badge = 'bg-rose-100 text-rose-800';
              if (db.classification === 'SENSITIVE') badge = 'bg-amber-100 text-amber-800';

              return (
                <div key={db.table_name} className="p-3 bg-stone-100/70 rounded-xl border border-stone-200">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="font-mono font-bold text-xs text-stone-900">
                      {db.table_name}
                    </span>
                    <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${badge}`}>
                      {db.classification}
                    </span>
                  </div>
                  <div className="text-[11px] text-stone-600">
                    {db.description} • {db.row_count} records
                  </div>
                </div>
              );
            })}
          </div>

          {/* Synthetic Data Note */}
          <div className="mt-4 p-3 rounded-xl bg-amber-50/70 border border-amber-200/80 text-[10px] font-mono text-amber-900 flex items-start gap-2">
            <Info className="w-3.5 h-3.5 text-amber-700 shrink-0 mt-0.5" />
            <span>
              <strong>Data-Source Agnostic</strong>: Demo resources use synthetic data for safe, reproducible demonstration. AgentGuard protects agents operating on real files, APIs, and databases identically.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
