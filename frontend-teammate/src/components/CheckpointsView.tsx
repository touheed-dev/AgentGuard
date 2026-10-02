import React, { useState } from 'react';
import {
  History, CheckCircle2, AlertTriangle, Plus, Play, Database,
  ShieldCheck, Fingerprint, Layers, Lock, Sparkles
} from 'lucide-react';
import { CheckpointSnapshot, MilestoneResult } from '../types';

interface CheckpointsViewProps {
  checkpoints: CheckpointSnapshot[];
  milestones: MilestoneResult[];
  onCreateCheckpoint: (name: string, description: string) => Promise<void>;
  onRunMilestones: () => Promise<void>;
  isRunningMilestones: boolean;
}

const MILESTONE_ICONS = [ShieldCheck, Database, Fingerprint, Lock, Sparkles];

export const CheckpointsView: React.FC<CheckpointsViewProps> = ({
  checkpoints,
  milestones,
  onCreateCheckpoint,
  onRunMilestones,
  isRunningMilestones,
}) => {
  const [showModal, setShowModal] = useState(false);
  const [ckptName, setCkptName] = useState('');
  const [ckptDesc, setCkptDesc] = useState('');
  const [selected, setSelected] = useState<CheckpointSnapshot | null>(checkpoints[0] || null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ckptName.trim()) return;
    await onCreateCheckpoint(ckptName, ckptDesc);
    setCkptName(''); setCkptDesc('');
    setShowModal(false);
  };

  const passedCount = milestones.filter((m) => m.status === 'VERIFIED').length;

  return (
    <div className="space-y-4 tab-enter">
      {/* Banner */}
      <div className="relative rounded-xl border px-5 py-4 overflow-hidden" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
        <div className="absolute inset-0 cyber-grid opacity-20 pointer-events-none" />
        <div className="absolute top-0 right-0 w-48 h-28 bg-purple-500/5 blur-3xl pointer-events-none" />
        <div className="relative flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-7 h-7 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                <History className="w-3.5 h-3.5 text-purple-600" />
              </div>
              <h2 className="text-base font-bold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                Security Checkpoints & Verification Suite
              </h2>
              <span className="text-[9px] font-mono px-2 py-0.5 rounded-full border" style={{ background: 'rgba(124,58,237,0.08)', borderColor: 'rgba(124,58,237,0.3)', color: '#6D28D9' }}>
                M1–M5 Architecture
              </span>
            </div>
            <p className="text-[11px] font-mono" style={{ color: '#7A6F62' }}>
              Tamper-evident state snapshots · Ledger integrity proofs · Security invariant verification
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onRunMilestones}
              disabled={isRunningMilestones}
              className="btn-primary flex items-center gap-2 px-3 py-2 rounded-xl text-xs disabled:opacity-50"
            >
              {isRunningMilestones ? (
                <><div className="w-3.5 h-3.5 border-2 border-emerald-400/30 border-t-emerald-400 rounded-full animate-spin" />Running…</>
              ) : (
                <><Play className="w-3.5 h-3.5" />Run M1–M5 Verification</>
              )}
            </button>
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-mono font-bold border transition-all"
              style={{ background: '#FAF7F2', borderColor: '#D6CFC3', color: '#6D28D9' }}
            >
              <Plus className="w-3.5 h-3.5" />
              New Checkpoint
            </button>
          </div>
        </div>
      </div>

      {/* Milestones M1–M5 */}
      <div>
        <div className="text-[9px] font-mono uppercase tracking-widest mb-3 px-1 flex items-center justify-between" style={{ color: '#7A6F62' }}>
          <span>Security Invariant Milestones</span>
          <span className="font-bold text-emerald-700">{passedCount}/{milestones.length} Verified</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
          {milestones.map((m, i) => {
            const Icon = MILESTONE_ICONS[i % MILESTONE_ICONS.length];
            const isPass = m.status === 'VERIFIED';
            return (
              <div
                key={m.milestone_id}
                className="relative rounded-xl border p-4 overflow-hidden transition-all duration-200 hover-lift"
                style={{
                  background: '#FAF7F2',
                  borderColor: isPass ? '#86EFAC' : '#FCA5A5',
                  boxShadow: '0 2px 8px rgba(100,85,70,0.06)',
                }}
              >
                <div className="flex items-center justify-between mb-3">
                  <div
                    className="w-8 h-8 rounded-xl flex items-center justify-center border"
                    style={isPass
                      ? { background: 'rgba(5,150,105,0.1)', borderColor: 'rgba(5,150,105,0.3)' }
                      : { background: 'rgba(220,38,38,0.1)', borderColor: 'rgba(220,38,38,0.3)' }
                    }
                  >
                    <Icon className="w-4 h-4" style={{ color: isPass ? '#047857' : '#B91C1C' }} />
                  </div>
                  <span
                    className="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full border"
                    style={isPass
                      ? { background: 'rgba(5,150,105,0.1)', color: '#047857', borderColor: 'rgba(5,150,105,0.3)' }
                      : { background: 'rgba(220,38,38,0.1)', color: '#B91C1C', borderColor: 'rgba(220,38,38,0.3)' }
                    }
                  >
                    {m.status}
                  </span>
                </div>

                <div className="font-mono text-[10px] mb-1" style={{ color: '#7A6F62' }}>{m.milestone_id}</div>
                <div className="text-xs font-bold mb-2 leading-tight" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                  {m.title}
                </div>
                <p className="text-[9px] leading-relaxed" style={{ color: '#5C5245' }}>{m.details}</p>

                {/* Metrics */}
                <div className="mt-3 pt-2 border-t space-y-1" style={{ borderColor: '#D6CFC3' }}>
                  {Object.entries(m.metrics).slice(0, 2).map(([k, v]) => (
                    <div key={k} className="flex items-center justify-between text-[9px] font-mono">
                      <span className="truncate" style={{ color: '#7A6F62' }}>{k.replace(/_/g, ' ')}</span>
                      <span className="font-bold ml-2 flex-shrink-0" style={{ color: isPass ? '#047857' : '#B91C1C' }}>{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Checkpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Checkpoint List */}
        <div className="lg:col-span-5 rounded-xl border p-4 flex flex-col" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
          <div className="flex items-center justify-between mb-3">
            <span className="text-sm font-semibold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
              State Snapshots
            </span>
            <span className="text-[9px] font-mono" style={{ color: '#7A6F62' }}>{checkpoints.length} saved</span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2 max-h-80">
            {checkpoints.length === 0 ? (
              <div className="h-24 flex items-center justify-center text-xs" style={{ color: '#8A7E70' }}>
                No checkpoints yet. Create the first one.
              </div>
            ) : (
              checkpoints.map((ckpt) => (
                <button
                  key={ckpt.checkpoint_id}
                  onClick={() => setSelected(ckpt)}
                  className="w-full text-left rounded-xl border px-3 py-2.5 transition-all duration-150"
                  style={selected?.checkpoint_id === ckpt.checkpoint_id
                    ? { background: '#FAF7F2', borderColor: '#A89E90', boxShadow: '0 2px 8px rgba(100,85,70,0.15)' }
                    : { background: '#F5F0E8', borderColor: '#D6CFC3' }
                  }
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[9px]" style={{ color: '#7A6F62' }}>{ckpt.checkpoint_id}</span>
                    <span className="text-[9px]" style={{ color: '#8A7E70' }}>{new Date(ckpt.timestamp * 1000).toLocaleString()}</span>
                  </div>
                  <div className="text-xs font-semibold truncate" style={{ color: '#1E232A' }}>{ckpt.name}</div>
                  <div className="flex items-center gap-3 mt-1 text-[9px] font-mono" style={{ color: '#7A6F62' }}>
                    <span>Ledger #{ckpt.ledger_height}</span>
                    <span>·</span>
                    <span>{ckpt.total_interceptions} events</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Selected Checkpoint Detail (7 cols) */}
        <div className="lg:col-span-7 rounded-xl border p-4" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
          {selected ? (
            <>
              <div className="flex items-center gap-2 mb-4">
                <div className="w-8 h-8 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                  <Database className="w-4 h-4 text-purple-600" />
                </div>
                <div>
                  <div className="text-xs font-bold" style={{ color: '#1E232A' }}>{selected.name}</div>
                  <div className="text-[9px] font-mono" style={{ color: '#7A6F62' }}>{selected.checkpoint_id}</div>
                </div>
                <div className="ml-auto text-right">
                  <div className="text-[9px] font-mono" style={{ color: '#7A6F62' }}>Created</div>
                  <div className="text-[10px] font-mono" style={{ color: '#5C5245' }}>{new Date(selected.timestamp * 1000).toLocaleString()}</div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 mb-4">
                {[
                  { label: 'Ledger Height', value: `#${selected.ledger_height}`, color: '#2563EB' },
                  { label: 'Total Interceptions', value: selected.total_interceptions, color: '#1E232A' },
                  { label: 'Quarantined Agents', value: selected.quarantined_agents_count, color: selected.quarantined_agents_count > 0 ? '#B91C1C' : '#047857' },
                  { label: 'Pending Approvals', value: selected.pending_approvals_count, color: selected.pending_approvals_count > 0 ? '#B45309' : '#047857' },
                  { label: 'Policy Epoch', value: `v${selected.policy_epoch}`, color: '#6D28D9' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="rounded-xl border p-3" style={{ background: '#FAF7F2', borderColor: '#D6CFC3' }}>
                    <div className="text-[9px] font-mono uppercase tracking-widest mb-1" style={{ color: '#7A6F62' }}>{label}</div>
                    <div className="text-xl font-black font-mono" style={{ color }}>{value}</div>
                  </div>
                ))}
              </div>

              {selected.description && (
                <p className="text-[11px] mb-4" style={{ color: '#5C5245' }}>{selected.description}</p>
              )}

              <div className="rounded-xl p-3 font-mono text-[10px] space-y-1.5 border" style={{ background: '#FAF7F2', borderColor: '#D6CFC3' }}>
                <div className="uppercase tracking-widest text-[9px] mb-2 font-bold" style={{ color: '#7A6F62' }}>Cryptographic Proof</div>
                <div className="flex items-start gap-2">
                  <span className="flex-shrink-0" style={{ color: '#7A6F62' }}>HEAD HASH:</span>
                  <span className="break-all" style={{ color: '#047857' }}>{selected.ledger_head_hash}</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="flex-shrink-0" style={{ color: '#7A6F62' }}>STATE SIG:</span>
                  <span className="break-all" style={{ color: '#2563EB' }}>{selected.state_signature}</span>
                </div>
              </div>
            </>
          ) : (
            <div className="h-40 flex items-center justify-center text-xs" style={{ color: '#8A7E70' }}>
              Select a checkpoint to view details
            </div>
          )}
        </div>
      </div>

      {/* Create Checkpoint Modal */}
      {showModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(50,40,30,0.5)', backdropFilter: 'blur(8px)' }}
          onClick={(e) => e.target === e.currentTarget && setShowModal(false)}
        >
          <div className="rounded-2xl border p-6 w-full max-w-md anim-fade-up shadow-2xl" style={{ background: '#EDE8DE', borderColor: '#D6CFC3' }}>
            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center">
                <Plus className="w-5 h-5 text-purple-600" />
              </div>
              <div>
                <h3 className="text-base font-bold" style={{ fontFamily: 'Space Grotesk', color: '#1E232A' }}>
                  Create Checkpoint
                </h3>
                <p className="text-[10px] font-mono" style={{ color: '#7A6F62' }}>Commit current security state to ledger</p>
              </div>
            </div>

            <form onSubmit={handleCreate} className="space-y-3">
              <div>
                <label className="text-[10px] font-mono uppercase tracking-widest block mb-1.5" style={{ color: '#7A6F62' }}>Checkpoint Name *</label>
                <input
                  type="text"
                  value={ckptName}
                  onChange={(e) => setCkptName(e.target.value)}
                  placeholder="e.g. Post-Incident Security Baseline"
                  className="input-cyber w-full text-sm px-3 py-2.5 rounded-xl"
                  required
                  autoFocus
                />
              </div>
              <div>
                <label className="text-[10px] font-mono uppercase tracking-widest block mb-1.5" style={{ color: '#7A6F62' }}>Description (optional)</label>
                <textarea
                  rows={3}
                  value={ckptDesc}
                  onChange={(e) => setCkptDesc(e.target.value)}
                  placeholder="Context or reason for this checkpoint…"
                  className="input-cyber w-full text-sm px-3 py-2 rounded-xl resize-none"
                />
              </div>
              <div className="flex gap-2 pt-2">
                <button type="submit" className="btn-primary flex-1 py-2.5 rounded-xl text-sm font-bold">
                  Create & Commit
                </button>
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="flex-1 py-2.5 rounded-xl text-sm font-mono font-bold border transition-colors"
                  style={{ background: '#FAF7F2', borderColor: '#D6CFC3', color: '#5C5245' }}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
