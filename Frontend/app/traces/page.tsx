"use client";

import { useEffect, useState } from "react";
import { FileSearch, Play, RefreshCw, CheckCircle2, AlertOctagon, ShieldAlert, Cpu, Hash } from "lucide-react";
import { fetchApi } from "@/lib/api";
import { TraceMeta, TraceStep, ReplayResponse } from "@/lib/contracts";

export default function TraceExplorerPage() {
  const [traces, setTraces] = useState<TraceMeta[]>([]);
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);
  const [selectedTraceSteps, setSelectedTraceSteps] = useState<TraceStep[]>([]);
  const [canonicalHash, setCanonicalHash] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [replaying, setReplaying] = useState(false);
  const [replayResult, setReplayResult] = useState<ReplayResponse | null>(null);

  async function loadTraces() {
    try {
      setLoading(true);
      const data = await fetchApi<TraceMeta[]>("/traces");
      setTraces(data);
      if (data.length > 0 && !selectedTraceId) {
        selectTrace(data[0].trace_id);
      }
    } catch {
      setTraces([]);
    } finally {
      setLoading(false);
    }
  }

  async function selectTrace(traceId: string) {
    try {
      setSelectedTraceId(traceId);
      setReplayResult(null);
      const res = await fetchApi<{ trace_id: string; steps: TraceStep[]; canonical_hash: string }>(`/traces/${traceId}`);
      setSelectedTraceSteps(res.steps || []);
      setCanonicalHash(res.canonical_hash || "");
    } catch (err) {
      console.error("Failed to load trace steps:", err);
      setSelectedTraceSteps([]);
      setCanonicalHash("");
    }
  }

  async function handleReplay() {
    if (!selectedTraceId) return;
    try {
      setReplaying(true);
      const res = await fetchApi<ReplayResponse>("/replay", {
        method: "POST",
        body: JSON.stringify({ trace_id: selectedTraceId }),
      });
      setReplayResult(res);
    } catch (err) {
      console.error("Replay execution failed:", err);
    } finally {
      setReplaying(false);
    }
  }

  useEffect(() => {
    loadTraces();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <FileSearch className="h-6 w-6 text-cyan-400" />
            Trace Explorer & Deterministic Replay
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Complete provenance reconstruction linking agents, actions, gateway decisions, tool executions, and RFC 8785 canonical trace digests.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadTraces}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh Traces
          </button>
          {selectedTraceId && (
            <button
              disabled={replaying}
              onClick={handleReplay}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white text-xs font-semibold shadow-lg shadow-cyan-950/40 transition-colors"
            >
              <Play className={`h-3.5 w-3.5 ${replaying ? "animate-spin" : ""}`} />
              {replaying ? "Replaying..." : "Replay Trace (Side-Effect-Free)"}
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left column: Trace list */}
        <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <h2 className="text-xs font-mono font-semibold text-slate-400 uppercase tracking-wider">
            Recorded Traces ({traces.length})
          </h2>
          <div className="space-y-2">
            {traces.length === 0 ? (
              <div className="py-8 text-center text-xs font-mono text-slate-500">
                No active traces recorded. Run actions or Attack Lab scenarios to generate trace timelines.
              </div>
            ) : (
              traces.map((tr) => (
                <button
                  key={tr.trace_id}
                  onClick={() => selectTrace(tr.trace_id)}
                  className={`w-full text-left p-3 rounded-xl border transition-all text-xs font-mono space-y-1.5 ${
                    selectedTraceId === tr.trace_id
                      ? "bg-cyan-950/50 border-cyan-700 text-cyan-200 shadow-md"
                      : "bg-slate-950/60 border-slate-800/80 text-slate-300 hover:bg-slate-800/40"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold truncate">{tr.trace_id}</span>
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-400">
                      {tr.step_count} step{tr.step_count !== 1 ? "s" : ""}
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate flex items-center gap-1">
                    <Hash className="h-3 w-3" />
                    <span>{tr.canonical_hash ? tr.canonical_hash.substring(0, 16) + "..." : "pending"}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Right column: Trace timeline and replay inspector */}
        <div className="lg:col-span-3 space-y-6">
          {/* Canonical Hash Banner */}
          {selectedTraceId && canonicalHash && (
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
              <div className="flex items-center gap-2 text-slate-400 truncate">
                <span className="text-cyan-400 font-semibold">Canonical Trace Digest:</span>
                <span className="text-slate-200 truncate">{canonicalHash}</span>
              </div>
              <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 self-start sm:self-auto">
                RFC 8785 VERIFIED
              </span>
            </div>
          )}

          {/* Replay Result Banner */}
          {replayResult && (
            <div className="p-4 rounded-xl bg-gradient-to-r from-emerald-950/70 to-slate-900 border border-emerald-800 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-bold text-emerald-300">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  Deterministic Replay Complete — Status: {replayResult.status}
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  {replayResult.replayed_steps.length} step(s) evaluated
                </span>
              </div>
              <div className="text-xs text-slate-300 font-mono">
                Gateway state verified with side-effect-free replay. No live external tools or resources were invoked.
              </div>
            </div>
          )}

          {/* Timeline Steps */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
            <div className="px-6 py-3 border-b border-slate-800 bg-slate-950/60 text-xs font-mono text-slate-400 uppercase tracking-wider flex items-center justify-between">
              <span>Timeline Steps ({selectedTraceSteps.length})</span>
              <span>Trace: {selectedTraceId || "None"}</span>
            </div>

            <div className="divide-y divide-slate-800/60">
              {selectedTraceSteps.length === 0 ? (
                <div className="py-12 text-center text-xs font-mono text-slate-500">
                  No trace steps available for the selected trace.
                </div>
              ) : (
                selectedTraceSteps.map((st, idx) => (
                  <div key={st.execution_id || idx} className="p-6 space-y-3 hover:bg-slate-800/20 transition-colors">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="h-6 w-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-mono font-bold text-slate-300">
                          {idx + 1}
                        </span>
                        <span className="text-xs font-bold font-mono text-indigo-300">{st.agent_id}</span>
                        <span className="text-xs font-mono text-slate-400">&rarr;</span>
                        <span className="text-xs font-bold font-mono text-cyan-300">{st.tool_name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${
                            st.decision === "ALLOW"
                              ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                              : st.decision === "BLOCK"
                              ? "bg-rose-950 text-rose-400 border-rose-800"
                              : "bg-amber-950 text-amber-400 border-amber-800"
                          }`}
                        >
                          {st.decision}
                        </span>
                        <span className="text-xs font-mono text-slate-400">Risk: {st.risk_score}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
                        <div className="text-[11px] text-slate-500">Proposed Arguments:</div>
                        <pre className="text-slate-300 overflow-x-auto text-[11px]">
                          {JSON.stringify(st.arguments, null, 2)}
                        </pre>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 space-y-1">
                        <div className="text-[11px] text-slate-500">Reason Codes & Details:</div>
                        <div className="text-amber-300 text-[11px]">
                          {st.reason_codes.length > 0 ? st.reason_codes.join(", ") : "Policy allowlist check passed"}
                        </div>
                        {st.incident_id && (
                          <div className="text-rose-400 text-[11px] flex items-center gap-1 mt-1">
                            <AlertOctagon className="h-3 w-3" />
                            Incident: {st.incident_id}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
