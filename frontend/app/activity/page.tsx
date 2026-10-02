"use client";

import { useEffect, useState } from "react";
import { Activity, ShieldAlert, CheckCircle2, AlertTriangle, ArrowRight, RefreshCw } from "lucide-react";
import { fetchApi } from "@/lib/api";

interface ActivityItem {
  id: string;
  time: string;
  agent: string;
  tool: string;
  outcome: "ALLOW" | "BLOCK" | "WARN" | "REQUIRE_APPROVAL";
  reasons: string[];
  risk_score: number;
}

export default function LiveActivityPage() {
  const [events, setEvents] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);

  async function loadActivity() {
    try {
      setLoading(true);
      const data = await fetchApi<ActivityItem[]>("/activity");
      setEvents(data);
    } catch {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadActivity();
    const interval = setInterval(loadActivity, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Activity className="h-6 w-6 text-cyan-400" />
            Live Gateway Activity Feed
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time authorization evaluations, tool executions, and security decisions.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
          <span className="text-xs font-mono text-emerald-400 font-semibold">STREAM ACTIVE</span>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="grid grid-cols-12 gap-2 px-6 py-3 border-b border-slate-800 bg-slate-950/60 text-xs font-mono text-slate-400 uppercase tracking-wider">
          <div className="col-span-2">Time</div>
          <div className="col-span-2">Agent ID</div>
          <div className="col-span-2">Target Tool</div>
          <div className="col-span-2">Decision</div>
          <div className="col-span-3">Reason / Details</div>
          <div className="col-span-1 text-right">Risk</div>
        </div>

        <div className="divide-y divide-slate-800/60">
          {events.length === 0 ? (
            <div className="py-12 text-center text-xs font-mono text-slate-500">
              No live activity events recorded yet. Execute actions or run Attack Lab scenarios to see real-time evaluations.
            </div>
          ) : (
            events.map((ev) => (
              <div key={ev.id} className="grid grid-cols-12 gap-2 px-6 py-4 items-center text-sm hover:bg-slate-800/30 transition-colors">
                <div className="col-span-2 font-mono text-xs text-slate-400">
                  {typeof ev.time === "number" ? new Date(ev.time * 1000).toLocaleTimeString() : ev.time || "N/A"}
                </div>
                <div className="col-span-2 font-mono text-xs text-slate-200">{ev.agent}</div>
                <div className="col-span-2 font-mono text-xs text-cyan-300">{ev.tool}</div>
                <div className="col-span-2">
                  <span
                    className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded border ${
                      ev.outcome === "ALLOW"
                        ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                        : ev.outcome === "BLOCK"
                        ? "bg-rose-950 text-rose-400 border-rose-800"
                        : "bg-amber-950 text-amber-400 border-amber-800"
                    }`}
                  >
                    {ev.outcome}
                  </span>
                </div>
                <div className="col-span-3 text-xs text-slate-300 truncate">
                  {ev.reasons && ev.reasons.length > 0 ? ev.reasons.join(", ") : "Standard capability granted"}
                </div>
                <div className="col-span-1 text-right font-mono text-xs font-semibold text-slate-300">
                  {ev.risk_score}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
