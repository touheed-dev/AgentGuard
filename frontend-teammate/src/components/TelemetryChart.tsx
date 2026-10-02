import React, { useMemo } from 'react';
import { Activity, Server, Zap, Radio } from 'lucide-react';
import { InterceptionDecision, AgentRecord } from '../types';

interface TelemetryChartProps {
  interceptions: InterceptionDecision[];
  agents: AgentRecord[];
  isTrafficGenerating: boolean;
  onToggleTraffic: () => void;
}

const DECISION_COLORS: Record<string, string> = {
  ALLOW: '#34d399',
  WARN: '#fbbf24',
  REQUIRE_APPROVAL: '#a78bfa',
  BLOCK: '#f87171',
};

export const TelemetryChart: React.FC<TelemetryChartProps> = ({
  interceptions,
  agents,
  isTrafficGenerating,
  onToggleTraffic,
}) => {
  const recent = interceptions.slice(0, 30);
  const total = recent.length || 1;

  const allowCount = recent.filter((i) => i.decision === 'ALLOW').length;
  const blockCount = recent.filter((i) => i.decision === 'BLOCK').length;
  const approvalCount = recent.filter((i) => i.decision === 'REQUIRE_APPROVAL').length;
  const warnCount = recent.filter((i) => i.decision === 'WARN').length;

  const allowPct = Math.round((allowCount / total) * 100);
  const blockPct = Math.round((blockCount / total) * 100);
  const approvalPct = Math.round((approvalCount / total) * 100);
  const warnPct = Math.round((warnCount / total) * 100);

  // Compute avg latency from stage_results
  const avgLatency = useMemo(() => {
    if (recent.length === 0 || !recent[0].stage_results?.length) return 185;
    const total = recent[0].stage_results.reduce((s, st) => s + st.latency_us, 0);
    return Math.round(total);
  }, [recent]);

  // Build sparkline data (last 24 items, oldest first)
  const sparkItems = [...interceptions].reverse().slice(-24);

  // Donut chart segments (SVG)
  const donutData = [
    { label: 'ALLOW', count: allowCount, pct: allowPct, color: '#34d399' },
    { label: 'BLOCK', count: blockCount, pct: blockPct, color: '#f87171' },
    { label: 'APPROVAL', count: approvalCount, pct: approvalPct, color: '#a78bfa' },
    { label: 'WARN', count: warnCount, pct: warnPct, color: '#fbbf24' },
  ];

  const r = 28, cx = 36, cy = 36, circ = 2 * Math.PI * r;
  let offset = 0;
  const donutSegments = donutData.map((d) => {
    const dash = (d.pct / 100) * circ;
    const seg = { ...d, dash, offset, gap: circ - dash };
    offset += dash;
    return seg;
  });

  return (
    <div className="relative rounded-xl border p-4 mb-4 overflow-hidden scan-overlay" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
      {/* Cyber grid background */}
      <div className="absolute inset-0 cyber-grid opacity-40 pointer-events-none" />

      {/* Ambient glow */}
      <div className="absolute top-0 right-0 w-64 h-32 bg-emerald-500/5 blur-3xl pointer-events-none rounded-full" />
      <div className="absolute bottom-0 left-0 w-48 h-24 bg-blue-500/5 blur-3xl pointer-events-none rounded-full" />

      {/* Header */}
      <div className="relative flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b mb-4" style={{ borderColor: '#D6CFC3' }}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center border" style={{ background: '#E2DBD0', borderColor: '#D6CFC3' }}>
            <Activity className="w-4 h-4 text-emerald-600 anim-breathe" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-sm" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                Live Gateway Kernel Telemetry
              </span>
              <span className="flex items-center gap-1 text-[9px] font-mono px-2 py-0.5 rounded-full border" style={{ background: 'rgba(5,150,105,0.1)', borderColor: 'rgba(5,150,105,0.3)', color: '#047857' }}>
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-600 animate-ping" />
                ACTIVE
              </span>
            </div>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: '#7A6F62' }}>
              Inline Pre-Execution Interception • Zero-Trust Boundary
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-lg border" style={{ background: '#E2DBD0', borderColor: '#D6CFC3' }}>
            <span style={{ color: '#7A6F62' }}>Latency:</span>
            <span className="font-bold" style={{ color: '#047857' }}>{avgLatency} µs</span>
          </div>
          <button
            onClick={onToggleTraffic}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center gap-2 transition-all duration-200 ${
              isTrafficGenerating
                ? 'border shadow-[0_0_16px_rgba(217,119,6,0.15)]'
                : 'btn-primary rounded-lg px-3 py-1.5'
            }`}
            style={isTrafficGenerating ? { background: 'rgba(217,119,6,0.12)', borderColor: 'rgba(217,119,6,0.4)', color: '#B45309' } : {}}
          >
            <Zap className={`w-3.5 h-3.5 ${isTrafficGenerating ? 'animate-bounce text-amber-600' : ''}`} />
            {isTrafficGenerating ? 'Stop Traffic' : 'Start Swarm'}
          </button>
        </div>
      </div>

      {/* Main content grid */}
      <div className="relative grid grid-cols-1 md:grid-cols-12 gap-4 text-xs font-mono">

        {/* Sparkline + breakdown (7 cols) */}
        <div className="md:col-span-7 space-y-3">
          {/* Spark bars */}
          <div>
            <div className="flex items-center justify-between text-[9px] uppercase tracking-widest mb-1.5" style={{ color: '#7A6F62' }}>
              <span>Execution Telemetry Vector ({sparkItems.length} traces)</span>
              <span className="font-bold" style={{ color: '#047857' }}>0.00% POST-BLOCK</span>
            </div>
            <div className="flex items-end gap-1 h-10 px-2 py-1.5 rounded-lg border overflow-x-hidden" style={{ background: '#E2DBD0', borderColor: '#D6CFC3' }}>
              {sparkItems.map((item, idx) => {
                const col = DECISION_COLORS[item.decision] || '#64748b';
                const h = item.decision === 'BLOCK' ? '100%' : item.decision === 'WARN' ? '75%' : '55%';
                return (
                  <div
                    key={`${item.trace_id}-${idx}`}
                    className="flex-1 min-w-[6px] rounded-sm cursor-pointer group relative transition-all duration-200 hover:brightness-110"
                    style={{ height: h, backgroundColor: col, opacity: 0.75 + 0.25 * (idx / sparkItems.length) }}
                    title={`${item.decision} | ${item.tool_name} (Risk: ${item.risk_score})`}
                  >
                    <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:flex flex-col items-center z-50">
                      <div className="text-[9px] p-2 rounded-lg border whitespace-nowrap shadow-xl" style={{ background: '#FAF7F2', borderColor: '#D6CFC3', color: '#1E232A' }}>
                        <div className="font-bold" style={{ color: col }}>{item.decision}</div>
                        <div style={{ color: '#5C5245' }}>{item.tool_name}</div>
                        <div style={{ color: '#7A6F62' }}>Risk: {item.risk_score}/100</div>
                      </div>
                    </div>
                  </div>
                );
              })}
              {sparkItems.length === 0 && (
                <div className="flex-1 text-center text-[10px] self-center" style={{ color: '#7A6F62' }}>Awaiting traffic…</div>
              )}
            </div>
          </div>

          {/* Decision breakdown stacked bar */}
          <div className="space-y-2">
            <div className="w-full h-2 rounded-full overflow-hidden flex" style={{ background: '#D6CFC3' }}>
              <div style={{ width: `${allowPct}%` }} className="h-full bg-emerald-600 transition-all duration-700" />
              <div style={{ width: `${blockPct}%` }} className="h-full bg-red-600 transition-all duration-700" />
              <div style={{ width: `${approvalPct}%` }} className="h-full bg-purple-600 transition-all duration-700" />
              <div style={{ width: `${warnPct}%` }} className="h-full bg-amber-600 transition-all duration-700" />
            </div>

            <div className="grid grid-cols-4 gap-2">
              {donutData.map((d) => (
                <div key={d.label} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: d.color }} />
                  <span className="text-[9px]" style={{ color: '#7A6F62' }}>{d.label}</span>
                  <span className="ml-auto font-bold text-[9px]" style={{ color: d.color }}>{d.pct}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Donut + Agent roster (5 cols) */}
        <div className="md:col-span-5 grid grid-cols-2 gap-3">
          {/* Mini donut */}
          <div className="rounded-lg border p-3 flex flex-col items-center justify-center" style={{ background: '#E2DBD0', borderColor: '#D6CFC3' }}>
            <div className="text-[9px] uppercase tracking-widest mb-2" style={{ color: '#7A6F62' }}>Decision Split</div>
            <svg width="72" height="72" viewBox="0 0 72 72">
              <circle cx={cx} cy={cy} r={r} fill="none" stroke="#D6CFC3" strokeWidth="8" />
              {donutSegments.filter((d) => d.pct > 0).map((d, i) => (
                <circle
                  key={i}
                  cx={cx} cy={cy} r={r}
                  fill="none"
                  stroke={d.color}
                  strokeWidth="8"
                  strokeDasharray={`${d.dash} ${d.gap}`}
                  strokeDashoffset={-d.offset + circ * 0.25}
                />
              ))}
              <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle" fill="#047857" fontSize="10" fontWeight="bold" fontFamily="JetBrains Mono">
                {allowPct}%
              </text>
              <text x={cx} y={cy + 12} textAnchor="middle" dominantBaseline="middle" fill="#7A6F62" fontSize="6" fontFamily="JetBrains Mono">
                ALLOW
              </text>
            </svg>
          </div>

          {/* Agent mesh roster */}
          <div className="rounded-lg border p-3 flex flex-col" style={{ background: '#E2DBD0', borderColor: '#D6CFC3' }}>
            <div className="flex items-center gap-1 text-[9px] uppercase tracking-widest mb-2" style={{ color: '#7A6F62' }}>
              <Server className="w-3 h-3 text-emerald-600" />
              <span>Agent Mesh</span>
              <span className="ml-auto font-bold text-emerald-700">{agents.length}</span>
            </div>
            <div className="space-y-1.5 flex-1">
              {agents.map((ag) => (
                <div key={ag.agent_id} className="flex items-center justify-between">
                  <span className="text-[9px] truncate flex-1" style={{ color: '#3D3529' }}>{ag.agent_id}</span>
                  <span
                    className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ml-2 ${
                      ag.status === 'HEALTHY'
                        ? 'bg-emerald-500 pulse-green'
                        : ag.status === 'SUSPICIOUS'
                        ? 'bg-amber-500 pulse-amber'
                        : 'bg-red-500 pulse-red'
                    }`}
                  />
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
