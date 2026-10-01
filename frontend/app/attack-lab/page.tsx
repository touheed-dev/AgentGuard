"use client";

import { useState } from "react";
import { Zap, ShieldAlert, CheckCircle2, Play, AlertTriangle } from "lucide-react";
import { fetchApi } from "@/lib/api";

interface ScenarioResult {
  scenario_id: string;
  scenario_name: string;
  decision: string;
  reasons: string[];
  agent_security_state: string;
  agent_status: string;
  executed: boolean;
}

export default function AttackLabPage() {
  const [runningId, setRunningId] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, ScenarioResult>>({});

  const scenarios = [
    {
      id: "1",
      name: "Prompt Injection / Argument Tampering",
      desc: "Injects shell metacharacters and directory traversal into argument payloads.",
      threat: "Arbitrary Command Execution / Path Traversal",
    },
    {
      id: "2",
      name: "Capability Violation",
      desc: "Agent attempts to call a tool outside its cryptographic scope and allowlist.",
      threat: "Privilege Escalation / Unauthorized Tool Execution",
    },
    {
      id: "3",
      name: "Sensitive Resource Access",
      desc: "Attempts reading /etc/passwd, credentials, and private SSH keys.",
      threat: "Credential & Data Exfiltration",
    },
    {
      id: "4",
      name: "Unsafe Destination / SSRF",
      desc: "Targets private cloud metadata IP (169.254.169.254) and forbidden network endpoints.",
      threat: "Server-Side Request Forgery / Internal Network Scan",
    },
    {
      id: "5",
      name: "Honey Asset Exfiltration",
      desc: "References registered honeytoken AG-HONEY-7F92-XK11 in arguments.",
      threat: "High-Confidence Breach / Immediate Quarantine",
    },
    {
      id: "6",
      name: "Cumulative Escalation & Circuit Breaker",
      desc: "Generates rolling multi-event violations triggering breaker trip and agent suspension.",
      threat: "Persistent Attack Behavior / Cascade Prevention",
    },
  ];

  async function runScenario(id: string) {
    try {
      setRunningId(id);
      const res = await fetchApi<ScenarioResult>(`/attack-lab/run/${id}`, {
        method: "POST",
      });
      setResults((prev) => ({ ...prev, [id]: res }));
    } catch (err) {
      console.error("Scenario execution failed:", err);
    } finally {
      setRunningId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
          <Zap className="h-6 w-6 text-rose-500" />
          Interactive Attack Lab (6 P0 Scenarios)
        </h1>
        <p className="text-sm text-slate-400 mt-1">
          Execute real adversarial simulations through the authoritative Gateway to observe deterministic blocking, quarantine state, and incident containment.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {scenarios.map((sc) => {
          const res = results[sc.id];
          const isRunning = runningId === sc.id;
          return (
            <div
              key={sc.id}
              className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 shadow-lg flex flex-col justify-between space-y-4"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    Scenario {sc.id}
                  </span>
                  <span className="text-[11px] font-mono text-rose-400 font-semibold">{sc.threat}</span>
                </div>
                <h3 className="text-base font-semibold text-white">{sc.name}</h3>
                <p className="text-xs text-slate-400">{sc.desc}</p>
              </div>

              {res && (
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Decision:</span>
                    <span
                      className={`px-2 py-0.5 rounded font-bold ${
                        res.decision === "BLOCK"
                          ? "bg-rose-950 text-rose-400 border border-rose-800"
                          : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                      }`}
                    >
                      {res.decision}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Reasons:</span>
                    <div className="text-amber-400 truncate">{res.reasons.join(", ") || "None"}</div>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Security State:</span>
                    <span className="text-cyan-400 font-bold">{res.agent_security_state}</span>
                  </div>
                </div>
              )}

              <button
                disabled={isRunning}
                onClick={() => runScenario(sc.id)}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 disabled:bg-slate-800 disabled:text-slate-600 text-white text-xs font-semibold shadow-lg shadow-rose-950/40 transition-colors"
              >
                <Play className={`h-3.5 w-3.5 ${isRunning ? "animate-spin" : ""}`} />
                {isRunning ? "Evaluating via Gateway..." : "Execute Scenario"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
