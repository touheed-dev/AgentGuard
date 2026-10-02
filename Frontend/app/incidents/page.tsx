"use client";

import { useEffect, useState } from "react";
import { AlertOctagon, ShieldAlert, CheckCircle, RefreshCw } from "lucide-react";
import { fetchApi } from "@/lib/api";
import { IncidentRecord } from "@/lib/contracts";

export default function IncidentCenterPage() {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [loading, setLoading] = useState(true);

  async function loadIncidents() {
    try {
      setLoading(true);
      const data = await fetchApi<IncidentRecord[]>("/incidents");
      setIncidents(data);
    } catch {
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncidents();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <AlertOctagon className="h-6 w-6 text-rose-500" />
            Security Incident Response Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic incident containment records with deduplicated event tracking and quarantine linkage.
          </p>
        </div>
        <button
          onClick={loadIncidents}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Incidents
        </button>
      </div>

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="grid grid-cols-12 gap-2 px-6 py-3 border-b border-slate-800 bg-slate-950/60 text-xs font-mono text-slate-400 uppercase tracking-wider">
          <div className="col-span-3">Incident ID</div>
          <div className="col-span-2">Agent ID</div>
          <div className="col-span-3">Reason Code</div>
          <div className="col-span-2">Severity</div>
          <div className="col-span-2 text-right">Containment State</div>
        </div>

        <div className="divide-y divide-slate-800/60">
          {incidents.length === 0 ? (
            <div className="py-12 text-center text-xs font-mono text-slate-500">
              No security incidents recorded. System running in safe baseline state.
            </div>
          ) : (
            incidents.map((inc) => (
              <div key={inc.incident_id} className="grid grid-cols-12 gap-2 px-6 py-4 items-center text-sm hover:bg-slate-800/30 transition-colors">
                <div className="col-span-3 font-mono text-xs text-rose-300 truncate">{inc.incident_id}</div>
                <div className="col-span-2 font-mono text-xs text-slate-200">{inc.agent_id}</div>
                <div className="col-span-3 font-mono text-xs text-amber-300">{inc.reason_code}</div>
                <div className="col-span-2">
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800">
                    {inc.severity.toUpperCase()}
                  </span>
                </div>
                <div className="col-span-2 text-right">
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                    {inc.state}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
