"use client";

import { useEffect, useState } from "react";
import { Share2, RefreshCw, Cpu, Shield, AlertTriangle } from "lucide-react";
import { fetchApi } from "@/lib/api";
import { GraphData } from "@/lib/contracts";

export default function AgentGraphPage() {
  const [graph, setGraph] = useState<GraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);

  async function loadGraph() {
    try {
      setLoading(true);
      const data = await fetchApi<GraphData>("/graph");
      setGraph(data);
    } catch {
      // Fallback display
      setGraph({
        nodes: [
          { id: "agent:planner-01", type: "agent", label: "Planner" },
          { id: "agent:researcher-01", type: "agent", label: "Researcher" },
          { id: "agent:coder-01", type: "agent", label: "Coder" },
          { id: "agent:executor-01", type: "agent", label: "Executor" },
          { id: "tool:echo", type: "tool", label: "Tool: Echo" },
        ],
        edges: [
          { source: "agent:planner-01", target: "agent:researcher-01", relationship: "communicates_with" },
          { source: "agent:planner-01", target: "agent:coder-01", relationship: "communicates_with" },
          { source: "agent:coder-01", target: "agent:executor-01", relationship: "communicates_with" },
        ],
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadGraph();
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Share2 className="h-6 w-6 text-indigo-400" />
            Agent Communication & Topology Graph
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Authoritative topology representing allowlisted agent communications, tool interactions, and security containment links.
          </p>
        </div>
        <button
          onClick={loadGraph}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Graph
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2 p-6 rounded-2xl bg-slate-900/60 border border-slate-800 min-h-[420px] flex flex-col justify-between">
          <div className="text-xs font-mono text-slate-500 uppercase">Interactive Topology Map</div>
          
          <div className="flex flex-wrap items-center justify-around gap-6 py-12">
            {graph.nodes.map((node) => {
              const isAgent = node.type === "agent";
              const isIncident = node.type === "incident";
              return (
                <div
                  key={node.id}
                  className={`p-4 rounded-xl border flex flex-col items-center gap-2 shadow-lg transition-transform hover:scale-105 ${
                    isIncident
                      ? "bg-rose-950/70 border-rose-800 text-rose-300"
                      : isAgent
                      ? "bg-indigo-950/70 border-indigo-800 text-indigo-200"
                      : "bg-slate-900 border-slate-700 text-slate-300"
                  }`}
                >
                  {isIncident ? (
                    <AlertTriangle className="h-6 w-6 text-rose-400" />
                  ) : isAgent ? (
                    <Cpu className="h-6 w-6 text-indigo-400" />
                  ) : (
                    <Shield className="h-6 w-6 text-cyan-400" />
                  )}
                  <span className="text-xs font-bold font-mono">{node.label}</span>
                  <span className="text-[10px] text-slate-400 font-mono">{node.type}</span>
                </div>
              );
            })}
          </div>

          <div className="text-xs text-slate-500 font-mono flex items-center justify-between border-t border-slate-800/80 pt-4">
            <span>Nodes: {graph.nodes.length}</span>
            <span>Authorized Edges: {graph.edges.length}</span>
          </div>
        </div>

        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <h2 className="text-sm font-semibold text-white">Authorized Paths</h2>
          <div className="divide-y divide-slate-800">
            {graph.edges.map((edge, idx) => (
              <div key={idx} className="py-2.5 text-xs font-mono space-y-1">
                <div className="flex items-center gap-2 text-slate-300">
                  <span className="text-cyan-400">{edge.source.replace("agent:", "")}</span>
                  <span>&rarr;</span>
                  <span className="text-indigo-400">{edge.target.replace("agent:", "")}</span>
                </div>
                <div className="text-[11px] text-slate-500">{edge.relationship}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
