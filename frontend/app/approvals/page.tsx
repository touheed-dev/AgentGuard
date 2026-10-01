"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, Clock, AlertTriangle, RefreshCw } from "lucide-react";
import { fetchApi } from "@/lib/api";
import { ApprovalRecord } from "@/lib/contracts";

export default function ApprovalCenterPage() {
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [processingId, setProcessingId] = useState<string | null>(null);

  async function loadApprovals() {
    try {
      setLoading(true);
      const data = await fetchApi<ApprovalRecord[]>("/approvals");
      setApprovals(data);
    } catch {
      setApprovals([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadApprovals();
  }, []);

  async function handleApprove(approval: ApprovalRecord) {
    try {
      setProcessingId(approval.approval_id);
      await fetchApi(`/approvals/${approval.approval_id}/approve`, {
        method: "POST",
        body: JSON.stringify(approval.fields || {}),
      });
      await loadApprovals();
    } catch (err) {
      console.error("Failed to approve action:", err);
    } finally {
      setProcessingId(null);
    }
  }

  async function handleReject(approvalId: string) {
    try {
      setProcessingId(approvalId);
      await fetchApi(`/approvals/${approvalId}/reject`, {
        method: "POST",
      });
      await loadApprovals();
    } catch (err) {
      console.error("Failed to reject action:", err);
    } finally {
      setProcessingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <CheckCircle2 className="h-6 w-6 text-emerald-400" />
            Human-in-the-Loop Approval Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Authoritative approval gating for sensitive actions with cryptographic freshness fingerprints.
          </p>
        </div>
        <button
          onClick={loadApprovals}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 text-xs font-medium text-slate-300 hover:bg-slate-700 hover:text-white transition-colors"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <div className="space-y-4">
        {approvals.length === 0 ? (
          <div className="p-12 text-center rounded-2xl border border-slate-800 bg-slate-900/40 text-xs font-mono text-slate-500">
            No pending action approvals. Autonomous execution operating under baseline policy.
          </div>
        ) : (
          approvals.map((app) => {
            const isPending = app.status === "APPROVAL_PENDING";
            return (
              <div
                key={app.approval_id}
                className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-mono font-semibold px-2 py-0.5 rounded border ${
                        isPending
                          ? "bg-amber-950 text-amber-400 border-amber-800"
                          : app.status === "APPROVED"
                          ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                          : "bg-rose-950 text-rose-400 border-rose-800"
                      }`}
                    >
                      {app.status}
                    </span>
                    <span className="text-xs font-mono text-slate-400 truncate max-w-xs">{app.approval_id}</span>
                  </div>
                  <div className="text-xs text-slate-300 font-mono bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <pre>{JSON.stringify(app.fields || { action: "Sensitive Tool Execution" }, null, 2)}</pre>
                  </div>
                </div>

                {isPending && (
                  <div className="flex items-center gap-3">
                    <button
                      disabled={processingId === app.approval_id}
                      onClick={() => handleApprove(app)}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-lg shadow-emerald-950/40 transition-colors"
                    >
                      <CheckCircle2 className="h-4 w-4" />
                      Approve
                    </button>
                    <button
                      disabled={processingId === app.approval_id}
                      onClick={() => handleReject(app.approval_id)}
                      className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold shadow-lg shadow-rose-950/40 transition-colors"
                    >
                      <XCircle className="h-4 w-4" />
                      Reject
                    </button>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
