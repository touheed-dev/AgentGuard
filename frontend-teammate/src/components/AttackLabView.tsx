import React, { useState } from 'react';
import { GitBranch, Play, CheckCircle2, AlertTriangle, Ban, ArrowRight, Shield, FlameKindling } from 'lucide-react';
import { ScenarioFixture, HoneypotAsset, ScenarioReplayResult } from '../types';

interface AttackLabViewProps {
  scenarios: ScenarioFixture[];
  honeypots: HoneypotAsset[];
  onReplayScenario: (scenarioId: string) => Promise<void> | Promise<ScenarioReplayResult>;
  isReplaying: boolean;
  replayResult: ScenarioReplayResult | null;
}

const CATEGORY_COLORS: Record<string, { text: string; bg: string; border: string }> = {
  'Data Exfiltration & Injection': { text: '#f87171', bg: 'rgba(248,113,113,0.08)', border: 'rgba(248,113,113,0.25)' },
  'Deception & Token Tripwire': { text: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.25)' },
  'Lateral Movement & Traversal': { text: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.25)' },
  'Code Execution & Sandbox Escape': { text: '#a78bfa', bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.25)' },
  'Capability Scope Violation': { text: '#60a5fa', bg: 'rgba(96,165,250,0.08)', border: 'rgba(96,165,250,0.25)' },
};

function getCategoryColor(cat: string) {
  return CATEGORY_COLORS[cat] || { text: '#94a3b8', bg: 'rgba(148,163,184,0.08)', border: 'rgba(148,163,184,0.2)' };
}

export const AttackLabView: React.FC<AttackLabViewProps> = ({
  scenarios,
  honeypots,
  onReplayScenario,
  isReplaying,
  replayResult,
}) => {
  const [selectedId, setSelectedId] = useState(scenarios[0]?.scenario_id || 'SCN-001');
  const active = scenarios.find((s) => s.scenario_id === selectedId) || scenarios[0];
  const catColor = active ? getCategoryColor(active.category) : getCategoryColor('');

  return (
    <div className="space-y-4 tab-enter">
      {/* Banner */}
      <div className="relative rounded-xl border px-5 py-4 overflow-hidden" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
        <div className="absolute inset-0 cyber-grid opacity-20 pointer-events-none" />
        <div className="absolute top-0 right-0 w-48 h-28 bg-red-500/5 blur-3xl pointer-events-none" />
        <div className="relative flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-7 h-7 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
                <GitBranch className="w-3.5 h-3.5 text-red-600" />
              </div>
              <h2 className="text-base font-bold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                Trace Replay & Attack Lab
              </h2>
              <span className="text-[9px] font-mono px-2 py-0.5 rounded-full border" style={{ background: 'rgba(220,38,38,0.08)', borderColor: 'rgba(220,38,38,0.3)', color: '#B91C1C' }}>
                SCN-001 → SCN-006
              </span>
            </div>
            <p className="text-[11px] font-mono" style={{ color: '#7A6F62' }}>
              Multi-agent attack chain DAGs · Counterfactual simulations · Deterministic replay proofs
            </p>
          </div>
          <button
            onClick={() => active && onReplayScenario(active.scenario_id)}
            disabled={isReplaying || !active}
            className="btn-primary flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs disabled:opacity-50"
          >
            {isReplaying ? (
              <><div className="w-4 h-4 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin" />Replaying…</>
            ) : (
              <><Play className="w-4 h-4" />Execute Replay ({active?.scenario_id})</>
            )}
          </button>
        </div>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">

        {/* Scenario selector (3 cols) */}
        <div className="lg:col-span-3 rounded-xl border p-3 space-y-2" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
          <div className="text-[9px] font-mono uppercase tracking-widest px-1 mb-3" style={{ color: '#7A6F62' }}>
            Attack Scenarios
          </div>
          {scenarios.map((scn) => {
            const sc = getCategoryColor(scn.category);
            const isActive = selectedId === scn.scenario_id;
            return (
              <button
                key={scn.scenario_id}
                onClick={() => setSelectedId(scn.scenario_id)}
                className="w-full text-left rounded-xl border p-3 transition-all duration-150"
                style={isActive
                  ? { background: '#FAF7F2', borderColor: '#A89E90', boxShadow: '0 2px 8px rgba(100,85,70,0.15)' }
                  : { background: '#F5F0E8', borderColor: '#D6CFC3' }
                }
              >
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="font-mono text-[9px]" style={{ color: '#7A6F62' }}>{scn.scenario_id}</span>
                  <span
                    className="text-[8px] font-bold font-mono px-1.5 py-0.5 rounded-full flex-shrink-0"
                    style={{ backgroundColor: sc.bg, color: sc.text, border: `1px solid ${sc.border}` }}
                  >
                    {scn.expected_decision}
                  </span>
                </div>
                <div className="text-[10px] font-medium leading-tight" style={{ color: '#1E232A' }}>{scn.title}</div>
                <div className="text-[9px] mt-0.5 truncate" style={{ color: '#7A6F62' }}>{scn.category}</div>
              </button>
            );
          })}
        </div>

        {/* Scenario detail + DAG (6 cols) */}
        <div className="lg:col-span-6 rounded-xl border p-4 space-y-4" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
          {active ? (
            <>
              {/* Header */}
              <div className="relative rounded-xl border p-4 overflow-hidden"
                style={{ backgroundColor: catColor.bg, borderColor: catColor.border }}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-[9px] font-mono uppercase tracking-widest mb-1" style={{ color: catColor.text }}>
                      {active.scenario_id} · {active.category}
                    </div>
                    <h3 className="text-sm font-bold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                      {active.title}
                    </h3>
                    <p className="text-[10px] mt-1.5 leading-relaxed" style={{ color: '#5C5245' }}>{active.description}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-[9px] font-mono uppercase" style={{ color: '#7A6F62' }}>Expected</div>
                    <span className="text-sm font-black font-mono" style={{ color: catColor.text }}>
                      {active.expected_decision}
                    </span>
                  </div>
                </div>
                <div className="mt-2 text-[9px] font-mono flex items-center gap-2" style={{ color: '#7A6F62' }}>
                  <Shield className="w-3 h-3" />
                  MITRE: {active.mitre_technique}
                </div>
              </div>

              {/* Attack DAG */}
              <div>
                <div className="text-[9px] font-mono uppercase tracking-widest mb-2" style={{ color: '#7A6F62' }}>
                  Attack Chain DAG
                </div>
                <div className="space-y-2">
                  {active.dag_nodes.map((node, i) => {
                    const nodeColor =
                      node.status === 'PASS' ? '#059669' :
                      node.status === 'BLOCK' ? '#DC2626' :
                      node.status === 'WARN' ? '#D97706' :
                      '#7C3AED';
                    return (
                      <div key={node.id} className="flex items-start gap-3">
                        {/* Connector */}
                        <div className="flex flex-col items-center shrink-0">
                          <div
                            className="w-7 h-7 rounded-full flex items-center justify-center border text-[10px] font-bold font-mono"
                            style={{ backgroundColor: `${nodeColor}15`, borderColor: `${nodeColor}40`, color: nodeColor }}
                          >
                            {node.step}
                          </div>
                          {i < active.dag_nodes.length - 1 && (
                            <div className="w-px h-4 mt-1" style={{ backgroundColor: `${nodeColor}30` }} />
                          )}
                        </div>

                        <div className="flex-1 rounded-xl border p-2.5 text-[10px] font-mono"
                          style={{ background: '#FAF7F2', borderColor: '#D6CFC3' }}>
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-bold" style={{ color: '#1E232A' }}>{node.label}</span>
                            <span className="font-bold" style={{ color: nodeColor }}>{node.status}</span>
                          </div>
                          <div style={{ color: '#5C5245' }}>
                            {node.agent_id} → <span style={{ color: '#1E232A' }}>{node.tool_name}</span>
                            <span className="ml-2" style={{ color: '#7A6F62' }}>Risk: <strong style={{ color: nodeColor }}>{node.risk}</strong></span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Failing stage info */}
              {active.failing_stage && (
                <div className="flex items-center gap-2 rounded-xl px-3 py-2 text-[10px] font-mono border" style={{ background: 'rgba(220,38,38,0.06)', borderColor: 'rgba(220,38,38,0.3)', color: '#B91C1C' }}>
                  <Ban className="w-3.5 h-3.5 flex-shrink-0" />
                  <span>Deterministic Block at Stage #{active.failing_stage}: <strong>{active.failing_stage_name}</strong></span>
                </div>
              )}
            </>
          ) : (
            <div className="h-40 flex items-center justify-center text-xs" style={{ color: '#8A7E70' }}>Select a scenario</div>
          )}
        </div>

        {/* Right: Replay result + Honeypots (3 cols) */}
        <div className="lg:col-span-3 space-y-4">
          {/* Replay Result */}
          {replayResult && (
            <div className="rounded-xl border p-4" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
              <div className="text-[9px] font-mono uppercase tracking-widest mb-3" style={{ color: '#7A6F62' }}>Last Replay Result</div>

              <div className="text-center py-3 rounded-xl mb-3 border" style={
                replayResult.deterministic_match
                  ? { background: 'rgba(5,150,105,0.08)', borderColor: 'rgba(5,150,105,0.3)' }
                  : { background: 'rgba(220,38,38,0.08)', borderColor: 'rgba(220,38,38,0.3)' }
              }>
                {replayResult.deterministic_match ? (
                  <CheckCircle2 className="w-8 h-8 mx-auto mb-1 text-emerald-600" />
                ) : (
                  <AlertTriangle className="w-8 h-8 mx-auto mb-1 text-red-600" />
                )}
                <div className="text-xs font-bold font-mono" style={{ color: replayResult.deterministic_match ? '#047857' : '#B91C1C' }}>
                  {replayResult.deterministic_match ? 'DETERMINISTIC MATCH' : 'MISMATCH DETECTED'}
                </div>
              </div>

              <div className="space-y-1.5 text-[10px] font-mono">
                <div className="flex justify-between">
                  <span style={{ color: '#7A6F62' }}>Expected:</span>
                  <span className="font-bold" style={{ color: '#1E232A' }}>{replayResult.expected}</span>
                </div>
                <div className="flex justify-between">
                  <span style={{ color: '#7A6F62' }}>Actual:</span>
                  <span className="font-bold" style={{ color: replayResult.actual === 'BLOCK' ? '#B91C1C' : '#047857' }}>
                    {replayResult.actual}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span style={{ color: '#7A6F62' }}>Risk Score:</span>
                  <span className="font-bold" style={{ color: '#1E232A' }}>{replayResult.decision?.risk_score}/100</span>
                </div>
              </div>
            </div>
          )}

          {/* Honeypot Assets */}
          <div className="rounded-xl border p-4" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
            <div className="flex items-center gap-2 mb-3">
              <FlameKindling className="w-4 h-4 text-amber-600" />
              <span className="text-xs font-semibold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                Deception Tripwires
              </span>
              <span className="ml-auto text-[9px] font-mono px-2 py-0.5 rounded-full border" style={{ background: 'rgba(217,119,6,0.1)', borderColor: 'rgba(217,119,6,0.3)', color: '#B45309' }}>
                {honeypots.length} ARMED
              </span>
            </div>
            <div className="space-y-2">
              {honeypots.map((hp, i) => (
                <div key={i} className="rounded-lg p-2.5 text-[10px] font-mono border" style={{ background: '#FAF7F2', borderColor: '#D6CFC3' }}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold" style={{ color: '#B45309' }}>{hp.type}</span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded border" style={{ background: 'rgba(217,119,6,0.1)', borderColor: 'rgba(217,119,6,0.3)', color: '#B45309' }}>
                      {hp.status}
                    </span>
                  </div>
                  <div className="truncate text-[9px]" style={{ color: '#5C5245' }}>{hp.token}</div>
                  <div className="mt-1 text-[9px]" style={{ color: '#8A7E70' }}>{hp.action_on_touch}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
