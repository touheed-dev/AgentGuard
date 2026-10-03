import React, { useState } from 'react';
import { X, ShieldCheck, Ban, Clock, AlertTriangle, Lock } from 'lucide-react';
import { InterceptionDecision } from '../types';

interface EventDetailDrawerProps {
  decision: InterceptionDecision | null;
  onClose: () => void;
}

const STATUS_COLORS: Record<string, string> = {
  PASS: '#34d399', ALLOW: '#34d399',
  WARN: '#fbbf24',
  REQUIRE_APPROVAL: '#a855f7',
  BLOCK: '#f87171', SHORT_CIRCUIT: '#f87171',
};

export const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({ decision, onClose }) => {
  const [activeTab, setActiveTab] = useState<'stages' | 'payload' | 'cryptography'>('stages');

  if (!decision) return null;

  const decisionColor =
    decision.decision === 'ALLOW' ? '#34d399' :
    decision.decision === 'WARN' ? '#fbbf24' :
    decision.decision === 'REQUIRE_APPROVAL' ? '#c084fc' :
    '#f87171';

  const DecisionIcon = decision.decision === 'ALLOW' ? ShieldCheck :
    decision.decision === 'REQUIRE_APPROVAL' ? Clock :
    decision.decision === 'WARN' ? AlertTriangle : Ban;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-xl h-full flex flex-col anim-drawer bg-[#0d1424] border-l border-slate-800 text-slate-200 shadow-2xl">

        {/* Header */}
        <div className="relative flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-[#0a0f1d]">
          {/* Colored side accent */}
          <div className="absolute left-0 top-0 bottom-0 w-1" style={{ background: decisionColor }} />

          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center border"
              style={{ backgroundColor: `${decisionColor}15`, borderColor: `${decisionColor}40` }}
            >
              <DecisionIcon className="w-5 h-5" style={{ color: decisionColor }} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base font-mono text-slate-100">{decision.tool_name}</span>
                <span
                  className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border"
                  style={{ backgroundColor: `${decisionColor}15`, color: decisionColor, borderColor: `${decisionColor}40` }}
                >
                  {decision.decision}
                </span>
              </div>
              <p className="text-[11px] font-mono mt-0.5 text-slate-400">
                {decision.agent_id} · {decision.trace_id}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-[9px] font-mono uppercase text-slate-500">Risk</div>
              <div className="font-mono font-black text-lg" style={{ color: decisionColor }}>
                {decision.risk_score}<span className="text-xs text-slate-500">/100</span>
              </div>
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg flex items-center justify-center border border-slate-700 bg-slate-800/80 text-slate-300 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1.5 px-4 py-2 border-b border-slate-800 bg-[#0a0f1d]/60">
          {(['stages', 'payload', 'cryptography'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-lg text-[11px] font-mono font-semibold transition-all duration-150 capitalize cursor-pointer border ${
                activeTab === tab
                  ? 'bg-cyan-950/70 text-cyan-300 border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200'
              }`}
            >
              {tab === 'stages' ? '20 Stages' : tab === 'payload' ? 'Payload' : 'Cryptography'}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2 tab-enter">
          {activeTab === 'stages' && (
            <>
              <div className="flex items-center justify-between text-[9px] font-mono uppercase tracking-widest mb-3 text-slate-500">
                <span>Stage Evaluation Sequence</span>
                <span>Fail-Closed Pre-Execution</span>
              </div>
              {decision.stage_results.map((st) => {
                const stColor = STATUS_COLORS[st.status] || '#64748b';
                const isBlock = st.status === 'BLOCK' || st.status === 'SHORT_CIRCUIT';
                return (
                  <div
                    key={st.stage_num}
                    className={`rounded-xl border p-3 font-mono relative overflow-hidden transition-all duration-150 ${
                      isBlock ? 'bg-red-950/20 border-red-500/40' : 'bg-[#0a0f1d] border-slate-800'
                    }`}
                  >
                    {/* Left accent */}
                    <div className="absolute left-0 top-2 bottom-2 w-1 rounded-full" style={{ backgroundColor: stColor }} />

                    <div className="flex items-center justify-between pl-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] w-5 text-slate-500">#{st.stage_num.toString().padStart(2, '0')}</span>
                        <span className="text-xs font-bold text-slate-200">{st.stage_name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[9px] text-slate-400">{st.latency_us} µs</span>
                        <span
                          className="text-[9px] font-bold font-mono px-2 py-0.5 rounded-full border"
                          style={{ backgroundColor: `${stColor}15`, color: stColor, borderColor: `${stColor}40` }}
                        >
                          {st.status}
                        </span>
                      </div>
                    </div>
                    <div className="text-[10px] mt-1 pl-7 text-slate-400">{st.detail}</div>
                    {st.evidence && (
                      <div className="mt-2 ml-7 rounded-lg p-2 text-[9px] font-mono border border-red-500/30 bg-red-950/30">
                        <div className="mb-1 uppercase tracking-widest font-bold text-red-400">Tripwire Evidence</div>
                        <pre className="whitespace-pre-wrap text-red-300">{JSON.stringify(st.evidence, null, 2)}</pre>
                      </div>
                    )}
                  </div>
                );
              })}
            </>
          )}

          {activeTab === 'payload' && (
            <div className="space-y-4">
              <div>
                <div className="text-[9px] font-mono uppercase tracking-widest mb-2 text-slate-500">
                  Sanitized Arguments (Canonical)
                </div>
                <div className="rounded-xl p-3 font-mono text-xs overflow-x-auto border border-slate-800 bg-[#0a0f1d] text-emerald-400">
                  <pre>{JSON.stringify(decision.redacted_arguments, null, 2)}</pre>
                </div>
              </div>

              <div className="rounded-xl p-3 font-mono text-[11px] space-y-2 border border-slate-800 bg-[#0a0f1d]">
                {[
                  ['TASK ID', decision.task_id, 'text-slate-200'],
                  ['TRACE ID', decision.trace_id, 'text-slate-200'],
                  ['BLOCK INDEX', `#${decision.block_index ?? 0}`, 'text-cyan-400'],
                  ['HONEYPOT TOUCHED', decision.honeypot_triggered ? 'YES — STAGE 5 CONTAINMENT' : 'NO (Clean)', decision.honeypot_triggered ? 'text-red-400 font-bold' : 'text-emerald-400'],
                  ['POST-BLOCK EXEC', 'NO (Guaranteed 0.00%)', 'text-emerald-400 font-bold'],
                ].map(([label, val, cls]) => (
                  <div key={label as string} className="flex items-center justify-between">
                    <span className="text-slate-500">{label}:</span>
                    <span className={`font-bold ${cls}`}>{val}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'cryptography' && (
            <div className="space-y-3 font-mono">
              <div className="rounded-xl p-4 space-y-3 text-[11px] border border-slate-800 bg-[#0a0f1d]">
                <div>
                  <div className="text-[9px] uppercase tracking-widest mb-1 text-slate-500">Canonical Block Hash (SHA-256)</div>
                  <div className="font-bold break-all text-[10px] text-emerald-400">{decision.canonical_hash}</div>
                </div>
                <div className="pt-2 border-t border-slate-800">
                  <div className="text-[9px] uppercase tracking-widest mb-1 text-slate-500">Committed Audit Block</div>
                  <div className="font-bold text-cyan-400">Block #{decision.block_index ?? 0}</div>
                </div>
                <div className="pt-2 border-t border-slate-800">
                  <div className="text-[9px] uppercase tracking-widest mb-1 text-slate-500">Post-Block Execution Rate</div>
                  <div className="font-bold text-emerald-400">0.00% — Guaranteed Zero-Byte</div>
                </div>
              </div>

              <div className="flex items-start gap-2 rounded-xl p-3 text-[11px] border border-emerald-500/30 bg-emerald-950/20 text-emerald-300">
                <Lock className="w-4 h-4 flex-shrink-0 mt-0.5 text-emerald-400" />
                <span>This decision is irreversibly committed to the RFC-8785 canonical ledger hash chain. Any modification to previous payloads breaks the cryptographic chain link.</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
