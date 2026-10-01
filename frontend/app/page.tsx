"use client";

import { useEffect, useState } from "react";
import { Shield, AlertOctagon, CheckCircle2, Cpu, Activity, Clock, Zap, ExternalLink } from "lucide-react";
import Link from "next/link";
import { fetchApi } from "@/lib/api";
import { AgentInfo, ToolInfo, IncidentRecord, ApprovalRecord } from "@/lib/contracts";

export default function CommandCenterPage() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      try {
        setLoading(true);
        const [agentsData, toolsData, incidentsData, approvalsData] = await Promise.all([
          fetchApi<AgentInfo[]>("/agents").catch(() => []),
          fetchApi<ToolInfo[]>("/tools").catch(() => []),
          fetchApi<IncidentRecord[]>("/incidents").catch(() => []),
          fetchApi<ApprovalRecord[]>("/approvals").catch(() => []),
        ]);
        setAgents(agentsData);
        setTools(toolsData);
        setIncidents(incidentsData);
        setApprovals(approvalsData);
      } catch (err: any) {
        setError(err.message || "Failed to connect to AgentGuard Gateway");
      } finally {
        setLoading(false);
      }
    }
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const quarantinedCount = agents.filter((a) => a.security_state === "QUARANTINED").length;
  const pendingApprovalsCount = approvals.filter((a) => a.status === "APPROVAL_PENDING").length;

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Banner / System State */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/40 border border-slate-800 shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="flex h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse" />
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
              Gateway Command Center
            </h1>
          </div>
          <p className="text-sm text-slate-400">
            Real-time control plane monitoring active autonomous agents, containment posture, and security gates.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href="/attack-lab"
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-rose-600 to-red-700 hover:from-rose-500 hover:to-red-600 text-white text-xs font-semibold shadow-lg shadow-rose-900/30 transition-all hover:scale-[1.02]"
          >
            <Zap className="h-4 w-4" />
            Launch Attack Lab
          </Link>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Agents</span>
            <div className="text-2xl font-bold font-mono text-white">{agents.length}</div>
            <span className="text-[11px] text-slate-500 font-mono">Bound to Task-1</span>
          </div>
          <div className="h-12 w-12 rounded-lg bg-blue-950/60 border border-blue-800/50 flex items-center justify-center text-blue-400">
            <Cpu className="h-6 w-6" />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Pending Approvals</span>
            <div className={`text-2xl font-bold font-mono ${pendingApprovalsCount > 0 ? "text-amber-400" : "text-white"}`}>
              {pendingApprovalsCount}
            </div>
            <span className="text-[11px] text-slate-500 font-mono">Human-in-the-loop</span>
          </div>
          <div className="h-12 w-12 rounded-lg bg-amber-950/60 border border-amber-800/50 flex items-center justify-center text-amber-400">
            <Clock className="h-6 w-6" />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Incidents Recorded</span>
            <div className={`text-2xl font-bold font-mono ${incidents.length > 0 ? "text-rose-400" : "text-white"}`}>
              {incidents.length}
            </div>
            <span className="text-[11px] text-slate-500 font-mono">Deterministic deduped</span>
          </div>
          <div className="h-12 w-12 rounded-lg bg-rose-950/60 border border-rose-800/50 flex items-center justify-center text-rose-400">
            <AlertOctagon className="h-6 w-6" />
          </div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Quarantine State</span>
            <div className={`text-2xl font-bold font-mono ${quarantinedCount > 0 ? "text-rose-400" : "text-emerald-400"}`}>
              {quarantinedCount > 0 ? `${quarantinedCount} Quarantined` : "All Clean"}
            </div>
            <span className="text-[11px] text-slate-500 font-mono">Circuit breaker status</span>
          </div>
          <div className={`h-12 w-12 rounded-lg ${quarantinedCount > 0 ? "bg-rose-950/60 border-rose-800/50 text-rose-400" : "bg-emerald-950/60 border-emerald-800/50 text-emerald-400"} border flex items-center justify-center`}>
            <Shield className="h-6 w-6" />
          </div>
        </div>
      </div>

      {/* Agents & Tools Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Agent Registry Card */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Cpu className="h-4 w-4 text-cyan-400" />
              Registered Agent Instances
            </h2>
            <span className="text-xs font-mono text-slate-500">Ed25519 Tokens Active</span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {agents.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-500 font-mono">
                No active agent identities detected
              </div>
            ) : (
              agents.map((agent) => (
                <div key={agent.agent_id} className="py-3 flex items-center justify-between">
                  <div className="space-y-0.5">
                    <div className="text-sm font-medium text-slate-200">{agent.name}</div>
                    <div className="text-xs font-mono text-slate-500">{agent.agent_id} &bull; epoch {agent.security_epoch}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                        agent.security_state === "QUARANTINED"
                          ? "bg-rose-950 text-rose-400 border-rose-800"
                          : "bg-emerald-950 text-emerald-400 border-emerald-800"
                      }`}
                    >
                      {agent.security_state}
                    </span>
                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                        agent.status === "suspended"
                          ? "bg-amber-950 text-amber-400 border-amber-800"
                          : "bg-slate-800 text-slate-300 border-slate-700"
                      }`}
                    >
                      {agent.status}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Tools Registry Card */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Shield className="h-4 w-4 text-indigo-400" />
              Verified Tool Registry
            </h2>
            <span className="text-xs font-mono text-slate-500">Schema Gated</span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {tools.length === 0 ? (
              <div className="py-6 text-center text-xs text-slate-500 font-mono">
                No tools registered
              </div>
            ) : (
              tools.map((t) => (
                <div key={t.tool_name} className="py-3 flex items-center justify-between">
                  <div className="space-y-0.5">
                    <div className="text-sm font-medium text-slate-200 font-mono">{t.tool_name}</div>
                    <div className="text-xs text-slate-400">{t.description}</div>
                  </div>
                  <div className="text-right">
                    <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/70 border border-cyan-800 px-2 py-0.5 rounded">
                      {t.required_capability}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
