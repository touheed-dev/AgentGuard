import React, { useState } from 'react';
import {
  Cpu, Play, CheckCircle2, AlertTriangle, Ban, Clock, Code2, Sliders, Zap, ArrowRight
} from 'lucide-react';
import { InterceptionDecision, StageResult } from '../types';

interface PipelineDeepDiveViewProps {
  currentDecision: InterceptionDecision | null;
  onSimulate: (payload: {
    agent_id: string;
    tool_name: string;
    arguments: Record<string, unknown>;
    task_id: string;
    trace_id: string;
  }) => Promise<void>;
  isSimulating: boolean;
}

const PRESET_PAYLOADS = [
  { name: '✅ Benign Document Search', agent_id: 'planner-01', tool_name: 'search_knowledge', task_id: 'TASK-DEMO-CLEAN', trace_id: 'TRC-CLEAN-01', arguments: { query: 'SOC-2 Compliance Report Q3' } },
  { name: '🍯 Honey Asset Tripwire (FR-16)', agent_id: 'planner-01', tool_name: 'read_file', task_id: 'TASK-DEMO-HONEY', trace_id: 'TRC-HONEY-02', arguments: { path: '/secrets/keys.txt', token: 'AG-HONEY-7F92-XK11' } },
  { name: '🔓 Path Traversal Escape', agent_id: 'coder-01', tool_name: 'read_file', task_id: 'TASK-DEMO-TRAVERSAL', trace_id: 'TRC-TRAVERSAL-03', arguments: { filepath: '../../../../etc/shadow' } },
  { name: '💉 SQL Tautology Injection', agent_id: 'researcher-01', tool_name: 'query_database', task_id: 'TASK-DEMO-SQLI', trace_id: 'TRC-SQLI-04', arguments: { query: "SELECT * FROM users WHERE user='admin' OR '1'='1';" } },
  { name: '⚠️ Arbitrary Code Execution', agent_id: 'coder-01', tool_name: 'execute_code', task_id: 'TASK-DEMO-CODE', trace_id: 'TRC-CODE-05', arguments: { language: 'python', code: "import subprocess; subprocess.run(['rm','-rf','/tmp'])" } },
  { name: '🚫 Capability Scope Violation', agent_id: 'external-scout', tool_name: 'execute_code', task_id: 'TASK-DEMO-SCOPE', trace_id: 'TRC-SCOPE-06', arguments: { script: 'test()' } },
];

const STATUS_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  PASS:             { bg: 'rgba(52,211,153,0.1)',   text: '#34d399', border: 'rgba(52,211,153,0.3)' },
  ALLOW:            { bg: 'rgba(52,211,153,0.1)',   text: '#34d399', border: 'rgba(52,211,153,0.3)' },
  WARN:             { bg: 'rgba(251,191,36,0.1)',   text: '#fbbf24', border: 'rgba(251,191,36,0.3)' },
  REQUIRE_APPROVAL: { bg: 'rgba(167,139,250,0.1)',  text: '#a78bfa', border: 'rgba(167,139,250,0.3)' },
  BLOCK:            { bg: 'rgba(248,113,113,0.1)',  text: '#f87171', border: 'rgba(248,113,113,0.3)' },
  SHORT_CIRCUIT:    { bg: 'rgba(248,113,113,0.1)',  text: '#f87171', border: 'rgba(248,113,113,0.3)' },
};

function StageIcon({ status }: { status: string }) {
  const props = { className: 'w-4 h-4' };
  if (status === 'PASS' || status === 'ALLOW') return <CheckCircle2 {...props} style={{ color: '#34d399' }} />;
  if (status === 'WARN') return <AlertTriangle {...props} style={{ color: '#fbbf24' }} />;
  if (status === 'REQUIRE_APPROVAL') return <Clock {...props} style={{ color: '#a78bfa' }} />;
  return <Ban {...props} style={{ color: '#f87171' }} />;
}

export const PipelineDeepDiveView: React.FC<PipelineDeepDiveViewProps> = ({
  currentDecision,
  onSimulate,
  isSimulating,
}) => {
  const [selectedPreset, setSelectedPreset] = useState(0);
  const [agentId, setAgentId] = useState(PRESET_PAYLOADS[0].agent_id);
  const [toolName, setToolName] = useState(PRESET_PAYLOADS[0].tool_name);
  const [taskId, setTaskId] = useState(PRESET_PAYLOADS[0].task_id);
  const [traceId, setTraceId] = useState(PRESET_PAYLOADS[0].trace_id);
  const [argsJson, setArgsJson] = useState(JSON.stringify(PRESET_PAYLOADS[0].arguments, null, 2));
  const [activeStage, setActiveStage] = useState<StageResult | null>(null);

  const handleApplyPreset = (index: number) => {
    setSelectedPreset(index);
    const p = PRESET_PAYLOADS[index];
    setAgentId(p.agent_id);
    setToolName(p.tool_name);
    setTaskId(p.task_id);
    setTraceId(p.trace_id);
    setArgsJson(JSON.stringify(p.arguments, null, 2));
  };

  const handleRunSimulation = async () => {
    try {
      await onSimulate({
        agent_id: agentId,
        tool_name: toolName,
        arguments: JSON.parse(argsJson) as Record<string, unknown>,
        task_id: taskId,
        trace_id: traceId || `TRC-${Date.now().toString().slice(-6)}`,
      });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      alert('Invalid JSON: ' + msg);
    }
  };

  const stages = currentDecision?.stage_results || [];
  const decisionColor = currentDecision
    ? (STATUS_COLORS[currentDecision.decision]?.text || '#64748b')
    : '#64748b';

  const totalLatency = stages.reduce((s, st) => s + st.latency_us, 0);

  return (
    <div className="space-y-4 tab-enter">
      {/* ── Banner ── */}
      <div className="relative rounded-xl border px-5 py-4 overflow-hidden" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
        <div className="absolute inset-0 cyber-grid opacity-30 pointer-events-none" />
        <div className="absolute top-0 right-0 w-48 h-32 bg-blue-500/5 blur-3xl pointer-events-none" />

        <div className="relative flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-7 h-7 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                <Cpu className="w-3.5 h-3.5 text-blue-600" />
              </div>
              <h2 className="text-base font-bold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                20-Stage Normative Pipeline Inspector
              </h2>
              <span className="text-[9px] font-mono px-2 py-0.5 rounded-full border" style={{ background: 'rgba(37,99,235,0.08)', borderColor: 'rgba(37,99,235,0.3)', color: '#1D4ED8' }}>
                CEL DETERMINISTIC
              </span>
            </div>
            <p className="text-[11px] font-mono" style={{ color: '#7A6F62' }}>
              Microsecond-level pre-execution telemetry. LLMs excluded from decision path.
            </p>
          </div>

          {currentDecision && (
            <div className="flex items-center gap-6">
              <div className="text-right">
                <div className="text-[9px] font-mono uppercase tracking-widest" style={{ color: '#7A6F62' }}>Decision</div>
                <span className="text-sm font-black font-mono px-3 py-1 rounded-lg mt-0.5 inline-block border"
                  style={{ backgroundColor: `${decisionColor}15`, color: decisionColor, borderColor: `${decisionColor}40` }}>
                  {currentDecision.decision}
                </span>
              </div>
              <div className="text-right">
                <div className="text-[9px] font-mono uppercase tracking-widest" style={{ color: '#7A6F62' }}>Risk Score</div>
                <div className="text-2xl font-black font-mono mt-0.5" style={{ color: decisionColor }}>
                  {currentDecision.risk_score}<span className="text-sm" style={{ color: '#8A7E70' }}>/100</span>
                </div>
              </div>
              <div className="text-right">
                <div className="text-[9px] font-mono uppercase tracking-widest" style={{ color: '#7A6F62' }}>Total Latency</div>
                <div className="text-sm font-black font-mono mt-0.5" style={{ color: '#1E232A' }}>
                  <span className="text-emerald-700">{totalLatency}</span>
                  <span className="text-xs" style={{ color: '#8A7E70' }}> µs</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Main Grid ── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">

        {/* Simulator (4 cols) */}
        <div className="lg:col-span-4 rounded-xl border p-4 space-y-4" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4" style={{ color: '#7A6F62' }} />
              <h3 className="text-sm font-semibold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                Payload Simulator
              </h3>
            </div>
            <span className="text-[9px] font-mono border px-2 py-0.5 rounded" style={{ color: '#7A6F62', borderColor: '#D6CFC3', background: '#E2DBD0' }}>LIVE INJECTOR</span>
          </div>

          {/* Preset selector */}
          <div>
            <label className="text-[10px] font-mono uppercase tracking-widest block mb-1.5" style={{ color: '#7A6F62' }}>
              Threat Scenario Preset
            </label>
            <select
              value={selectedPreset}
              onChange={(e) => handleApplyPreset(Number(e.target.value))}
              className="w-full text-xs rounded-lg px-3 py-2 border font-mono transition-colors"
              style={{ background: '#FAF7F2', borderColor: '#D6CFC3', color: '#1E232A' }}
            >
              {PRESET_PAYLOADS.map((p, i) => (
                <option key={p.name} value={i} style={{ background: '#FAF7F2', color: '#1E232A' }}>{p.name}</option>
              ))}
            </select>
          </div>

          {/* Fields */}
          <div className="grid grid-cols-2 gap-2">
            {[
              { label: 'AGENT_ID', value: agentId, set: setAgentId },
              { label: 'TOOL_NAME', value: toolName, set: setToolName },
              { label: 'TASK_ID', value: taskId, set: setTaskId },
              { label: 'TRACE_ID', value: traceId, set: setTraceId },
            ].map(({ label, value, set }) => (
              <div key={label}>
                <label className="text-[9px] font-mono uppercase tracking-widest block mb-1" style={{ color: '#7A6F62' }}>{label}</label>
                <input
                  type="text"
                  value={value}
                  onChange={(e) => set(e.target.value)}
                  className="input-cyber w-full text-[11px] px-2 py-1.5 rounded-lg"
                />
              </div>
            ))}
          </div>

          {/* JSON editor */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-[9px] font-mono uppercase tracking-widest" style={{ color: '#7A6F62' }}>Tool Arguments (JSON)</label>
              <Code2 className="w-3 h-3" style={{ color: '#7A6F62' }} />
            </div>
            <textarea
              rows={7}
              value={argsJson}
              onChange={(e) => setArgsJson(e.target.value)}
              className="input-cyber w-full text-[11px] px-3 py-2 rounded-xl resize-none"
              style={{ fontFamily: 'JetBrains Mono' }}
            />
          </div>

          <button
            onClick={handleRunSimulation}
            disabled={isSimulating}
            className="w-full btn-primary py-2.5 px-4 rounded-xl flex items-center justify-center gap-2 text-xs disabled:opacity-50"
          >
            {isSimulating ? (
              <>
                <div className="w-4 h-4 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin" />
                Interception In Progress…
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                Authorize at Gateway Boundary
              </>
            )}
          </button>
        </div>

        {/* Stage telemetry (8 cols) */}
        <div className="lg:col-span-8 rounded-xl border p-4 flex flex-col" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                Deterministic Stage Evaluation Flow
              </h3>
              <p className="text-[10px] font-mono" style={{ color: '#7A6F62' }}>20-Stage • Strict Pre-Execution Interception</p>
            </div>
            <span className="text-[10px] font-mono px-3 py-1 rounded-lg border" style={{ background: '#E2DBD0', borderColor: '#D6CFC3', color: '#7A6F62' }}>
              {stages.length} stages computed
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-1.5 max-h-[640px] pr-1">
            {stages.length === 0 ? (
              <div className="h-40 flex flex-col items-center justify-center text-xs" style={{ color: '#8A7E70' }}>
                <Cpu className="w-8 h-8 mb-2" style={{ color: '#8A7E70' }} />
                Run a simulation to view the 20-stage telemetry pipeline.
              </div>
            ) : (
              stages.map((st) => {
                const stClr = STATUS_COLORS[st.status] || { bg: 'rgba(100,116,139,0.1)', text: '#64748b', border: 'rgba(100,116,139,0.3)' };
                const isTerminal = st.status === 'BLOCK' || st.status === 'SHORT_CIRCUIT';
                return (
                  <div
                    key={st.stage_num}
                    onClick={() => setActiveStage(activeStage?.stage_num === st.stage_num ? null : st)}
                    className="relative rounded-xl border cursor-pointer transition-all duration-150 hover-lift overflow-hidden"
                    style={{
                      background: activeStage?.stage_num === st.stage_num
                        ? '#FAF7F2'
                        : isTerminal
                        ? 'rgba(239,68,68,0.05)'
                        : '#F5F0E8',
                      borderColor: activeStage?.stage_num === st.stage_num ? '#A89E90' : '#D6CFC3',
                    }}
                  >
                    {/* Left accent */}
                    <div className="absolute left-0 top-0 bottom-0 w-1 rounded-r" style={{ backgroundColor: stClr.text }} />

                    <div className="flex items-center justify-between px-3 py-2.5 pl-4">
                      <div className="flex items-center gap-2.5">
                        <span className="text-[9px] font-mono w-5 shrink-0" style={{ color: '#7A6F62' }}>
                          {st.stage_num.toString().padStart(2, '0')}
                        </span>
                        <StageIcon status={st.status} />
                        <span className="text-xs font-bold" style={{ color: '#1E232A' }}>{st.stage_name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[9px] font-mono" style={{ color: '#7A6F62' }}>{st.latency_us} µs</span>
                        <span
                          className="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border"
                          style={{ backgroundColor: stClr.bg, color: stClr.text, borderColor: stClr.border }}
                        >
                          {st.status}
                        </span>
                        {st.rule_matched && (
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border" style={{ background: '#E2DBD0', borderColor: '#D6CFC3', color: '#5C5245' }}>
                            {st.rule_matched}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Detail always shown */}
                    <div className="px-4 pb-2 pl-12 text-[10px]" style={{ color: '#5C5245' }}>{st.detail}</div>

                    {/* Expanded evidence */}
                    {activeStage?.stage_num === st.stage_num && st.evidence && (
                      <div className="mx-3 mb-3 ml-12 rounded-lg p-2.5 text-[9px] font-mono border" style={{ background: 'rgba(220,38,38,0.06)', borderColor: 'rgba(220,38,38,0.25)' }}>
                        <div className="uppercase tracking-widest mb-1 font-bold" style={{ color: '#B91C1C' }}>Tripwire Evidence</div>
                        <pre className="whitespace-pre-wrap" style={{ color: '#991B1B' }}>{JSON.stringify(st.evidence, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
