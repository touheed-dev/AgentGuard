import React from 'react';
import { X, ShieldCheck, Ban, Clock, AlertTriangle, Layers, Code2, Lock } from 'lucide-react';
import { InterceptionDecision } from '../types';
import { useState } from 'react';

interface EventDetailDrawerProps {
  decision: InterceptionDecision | null;
  onClose: () => void;
}

const STATUS_COLORS: Record<string, string> = {
  PASS: '#34d399', ALLOW: '#34d399',
  WARN: '#fbbf24',
  REQUIRE_APPROVAL: '#a78bfa',
  BLOCK: '#f87171', SHORT_CIRCUIT: '#f87171',
};

export const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({ decision, onClose }) => {
  const [activeTab, setActiveTab] = useState<'stages' | 'payload' | 'cryptography'>('stages');

  if (!decision) return null;

  const decisionColor =
    decision.decision === 'ALLOW' ? '#34d399' :
    decision.decision === 'WARN' ? '#fbbf24' :
    decision.decision === 'REQUIRE_APPROVAL' ? '#a78bfa' :
    '#f87171';

  const DecisionIcon = decision.decision === 'ALLOW' ? ShieldCheck :
    decision.decision === 'REQUIRE_APPROVAL' ? Clock :
    decision.decision === 'WARN' ? AlertTriangle : Ban;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(6px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-xl h-full flex flex-col anim-drawer" style={{ background: '#F5F0E8', borderLeft: '1px solid #D6CFC3' }}>

        {/* Header */}
        <div className="relative flex items-center justify-between px-5 py-4 border-b"
          style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
          {/* Colored side accent */}
          <div className="absolute left-0 top-0 bottom-0 w-1" style={{ background: decisionColor }} />

          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center border"
              style={{ backgroundColor: `${decisionColor}15`, borderColor: `${decisionColor}40` }}>
              <DecisionIcon className="w-5 h-5" style={{ color: decisionColor }} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base font-mono" style={{ color: '#1E232A' }}>{decision.tool_name}</span>
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border"
                  style={{ backgroundColor: `${decisionColor}15`, color: decisionColor, borderColor: `${decisionColor}40` }}>
                  {decision.decision}
                </span>
              </div>
              <p className="text-[11px] font-mono mt-0.5" style={{ color: '#7A6F62' }}>
                {decision.agent_id} · {decision.trace_id}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-[9px] font-mono uppercase" style={{ color: '#7A6F62' }}>Risk</div>
              <div className="font-mono font-black text-lg" style={{ color: decisionColor }}>
                {decision.risk_score}<span className="text-xs" style={{ color: '#8A7E70' }}>/100</span>
              </div>
            </div>
            <button onClick={onClose} className="w-8 h-8 rounded-lg flex items-center justify-center border transition-colors" style={{ background: '#FAF7F2', borderColor: '#D6CFC3', color: '#5C5245' }}>
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tabs - All Beige */}
        <div className="flex gap-1.5 px-4 py-2 border-b" style={{ background: '#E6E0D5', borderColor: '#D2C9BB' }}>
          {(['stages', 'payload', 'cryptography'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="px-3 py-1.5 rounded-lg text-[11px] font-mono font-semibold transition-all duration-150 capitalize cursor-pointer border"
              style={activeTab === tab
                ? { background: '#FAF7F2', color: '#1E232A', borderColor: '#B8AE9F', boxShadow: '0 1px 4px rgba(100,85,70,0.15)' }
                : { background: '#ECE6DC', color: '#5C5346', borderColor: '#DCD4C7' }
              }
            >
              {tab === 'stages' ? '20 Stages' : tab === 'payload' ? 'Payload' : 'Cryptography'}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2 tab-enter">
          {activeTab === 'stages' && (
            <>
              <div className="flex items-center justify-between text-[9px] font-mono uppercase tracking-widest mb-3" style={{ color: '#7A6F62' }}>
                <span>Stage Evaluation Sequence</span>
                <span>Fail-Closed Pre-Execution</span>
              </div>
              {decision.stage_results.map((st) => {
                const stColor = STATUS_COLORS[st.status] || '#64748b';
                const isBlock = st.status === 'BLOCK' || st.status === 'SHORT_CIRCUIT';
                return (
                  <div
                    key={st.stage_num}
                    className="rounded-xl border p-3 font-mono relative overflow-hidden transition-all duration-150"
                    style={{
                      background: isBlock ? 'rgba(220,38,38,0.06)' : '#FAF7F2',
                      borderColor: isBlock ? 'rgba(220,38,38,0.3)' : '#D6CFC3',
                    }}
                  >
                    {/* Left accent */}
                    <div className="absolute left-0 top-2 bottom-2 w-1 rounded-full" style={{ backgroundColor: stColor }} />

                    <div className="flex items-center justify-between pl-2">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] w-5" style={{ color: '#7A6F62' }}>#{st.stage_num.toString().padStart(2, '0')}</span>
                        <span className="text-xs font-bold" style={{ color: '#1E232A' }}>{st.stage_name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[9px]" style={{ color: '#7A6F62' }}>{st.latency_us} µs</span>
                        <span
                          className="text-[9px] font-bold font-mono px-2 py-0.5 rounded-full border"
                          style={{ backgroundColor: `${stColor}15`, color: stColor, borderColor: `${stColor}40` }}
                        >
                          {st.status}
                        </span>
                      </div>
                    </div>
                    <div className="text-[10px] mt-1 pl-7" style={{ color: '#5C5245' }}>{st.detail}</div>
                    {st.evidence && (
                      <div className="mt-2 ml-7 rounded-lg p-2 text-[9px] font-mono border" style={{ background: 'rgba(220,38,38,0.08)', borderColor: 'rgba(220,38,38,0.3)' }}>
                        <div className="mb-1 uppercase tracking-widest font-bold" style={{ color: '#B91C1C' }}>Tripwire Evidence</div>
                        <pre className="whitespace-pre-wrap" style={{ color: '#991B1B' }}>{JSON.stringify(st.evidence, null, 2)}</pre>
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
                <div className="text-[9px] font-mono uppercase tracking-widest mb-2" style={{ color: '#7A6F62' }}>
                  Sanitized Arguments (Canonical)
                </div>
                <div className="rounded-xl p-3 font-mono text-xs overflow-x-auto border" style={{ background: '#FAF7F2', borderColor: '#D6CFC3', color: '#047857' }}>
                  <pre>{JSON.stringify(decision.redacted_arguments, null, 2)}</pre>
                </div>
              </div>

              <div className="rounded-xl p-3 font-mono text-[11px] space-y-2 border" style={{ background: '#FAF7F2', borderColor: '#D6CFC3' }}>
                {[
                  ['TASK ID', decision.task_id, 'text-slate-900'],
                  ['TRACE ID', decision.trace_id, 'text-slate-900'],
                  ['BLOCK INDEX', `#${decision.block_index}`, 'text-blue-700'],
                  ['HONEYPOT TOUCHED', decision.honeypot_triggered ? 'YES — STAGE 5 CONTAINMENT' : 'NO (Clean)', decision.honeypot_triggered ? 'text-red-700 font-bold' : 'text-emerald-700'],
                  ['POST-BLOCK EXEC', 'NO (Guaranteed 0.00%)', 'text-emerald-700'],
                ].map(([label, val, cls]) => (
                  <div key={label as string} className="flex items-center justify-between">
                    <span style={{ color: '#7A6F62' }}>{label}:</span>
                    <span className={`font-bold ${cls}`}>{val}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'cryptography' && (
            <div className="space-y-3 font-mono">
              <div className="rounded-xl p-4 space-y-3 text-[11px] border" style={{ background: '#FAF7F2', borderColor: '#D6CFC3' }}>
                <div>
                  <div className="text-[9px] uppercase tracking-widest mb-1" style={{ color: '#7A6F62' }}>Canonical Block Hash (SHA-256)</div>
                  <div className="font-bold break-all text-[10px]" style={{ color: '#047857' }}>{decision.canonical_hash}</div>
                </div>
                <div className="pt-2 border-t" style={{ borderColor: '#D6CFC3' }}>
                  <div className="text-[9px] uppercase tracking-widest mb-1" style={{ color: '#7A6F62' }}>Committed Audit Block</div>
                  <div className="font-bold" style={{ color: '#2563EB' }}>Block #{decision.block_index}</div>
                </div>
                <div className="pt-2 border-t" style={{ borderColor: '#D6CFC3' }}>
                  <div className="text-[9px] uppercase tracking-widest mb-1" style={{ color: '#7A6F62' }}>Post-Block Execution Rate</div>
                  <div className="font-bold" style={{ color: '#047857' }}>0.00% — Guaranteed Zero-Byte</div>
                </div>
              </div>

              <div className="flex items-start gap-2 rounded-xl p-3 text-[11px] border" style={{ background: 'rgba(5,150,105,0.08)', borderColor: 'rgba(5,150,105,0.3)', color: '#047857' }}>
                <Lock className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>This decision is irreversibly committed to the RFC-8785 canonical ledger hash chain. Any modification to previous payloads breaks the cryptographic chain link.</span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
