import React, { useState, useEffect, useRef } from 'react';
import { Navbar, DashboardTab } from './components/Navbar';
import { RealtimeEcosystemView } from './components/RealtimeEcosystemView';
import { PipelineDeepDiveView } from './components/PipelineDeepDiveView';
import { AttackLabView } from './components/AttackLabView';
import { CheckpointsView } from './components/CheckpointsView';
import { RuntimeIntegrityView } from './components/RuntimeIntegrityView';
import { EventDetailDrawer } from './components/EventDetailDrawer';
import { api } from './api';
import {
  GatewayStats, InterceptionDecision, AgentRecord, ApprovalItem,
  LedgerBlock, ScenarioFixture, HoneypotAsset, CheckpointSnapshot, MilestoneResult,
  LedgerVerificationResult, ScenarioReplayResult
} from './types';
import { ShieldAlert, CheckCircle, X } from 'lucide-react';

// ─── Toast ──────────────────────────────────────────────────────────────────
function Toast({ title, message, type, onClose }: {
  title: string; message: string; type: 'alert' | 'success'; onClose: () => void;
}) {
  const isAlert = type === 'alert';
  return (
    <div
      className={`anim-fade-up flex items-start gap-3 px-4 py-3 rounded-xl border shadow-2xl max-w-sm w-full backdrop-blur-xl ${
        isAlert
          ? 'bg-red-950/90 border-red-500/50 text-red-100 shadow-[0_0_20px_rgba(239,68,68,0.3)]'
          : 'bg-emerald-950/90 border-emerald-500/50 text-emerald-100 shadow-[0_0_20px_rgba(16,185,129,0.3)]'
      }`}
    >
      <div
        className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
          isAlert ? 'bg-red-900/60' : 'bg-emerald-900/60'
        }`}
      >
        {isAlert ? (
          <ShieldAlert className="w-4 h-4 text-red-400" />
        ) : (
          <CheckCircle className="w-4 h-4 text-emerald-400" />
        )}
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-bold text-[10px] font-mono uppercase tracking-widest mb-0.5 opacity-90">
          {title}
        </div>
        <div className="text-xs text-slate-200">{message}</div>
      </div>
      <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors ml-1">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

export function App() {
  const [activeTab, setActiveTab] = useState<DashboardTab>('realtime-ecosystem');
  const [stats, setStats] = useState<GatewayStats | null>(null);
  const [interceptions, setInterceptions] = useState<InterceptionDecision[]>([]);
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [approvals, setApprovals] = useState<ApprovalItem[]>([]);
  const [ledgerBlocks, setLedgerBlocks] = useState<LedgerBlock[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioFixture[]>([]);
  const [honeypots, setHoneypots] = useState<HoneypotAsset[]>([]);
  const [checkpoints, setCheckpoints] = useState<CheckpointSnapshot[]>([]);
  const [milestones, setMilestones] = useState<MilestoneResult[]>([]);
  const [selectedInterception, setSelectedInterception] = useState<InterceptionDecision | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [isVerifyingLedger, setIsVerifyingLedger] = useState(false);
  const [ledgerVerification, setLedgerVerification] = useState<LedgerVerificationResult | null>(null);
  const [isReplaying, setIsReplaying] = useState(false);
  const [replayResult, setReplayResult] = useState<ScenarioReplayResult | null>(null);
  const [isRunningMilestones, setIsRunningMilestones] = useState(false);
  const [isTrafficGenerating, setIsTrafficGenerating] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [drawerDecision, setDrawerDecision] = useState<InterceptionDecision | null>(null);
  const [toasts, setToasts] = useState<Array<{ id: string; title: string; message: string; type: 'alert' | 'success' }>>([]);

  // ── TAB SCAN ANIMATION STATE ──
  const [contentScanProgress, setContentScanProgress] = useState(0);
  const [isContentScanning, setIsContentScanning] = useState(false);
  const contentScanRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  const showToast = (title: string, message: string, type: 'alert' | 'success' = 'alert') => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev.slice(-3), { id, title, message, type }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 5000);
  };

  const loadAllData = async () => {
    try {
      const [
        statsData, interceptionsData, agentsData, approvalsData,
        ledgerData, scenariosData, honeypotsData, checkpointsData, milestonesData
      ] = await Promise.all([
        api.getStats(), api.getInterceptions(50), api.getAgents(), api.getApprovals(),
        api.getLedger(50), api.getScenarios(), api.getHoneypots(),
        api.getCheckpoints(), api.runMilestones()
      ]);
      setStats(statsData);
      setInterceptions(interceptionsData);
      if (interceptionsData.length > 0 && !selectedInterception) setSelectedInterception(interceptionsData[0]);
      setAgents(agentsData);
      setApprovals(approvalsData);
      setLedgerBlocks(ledgerData);
      setScenarios(scenariosData);
      setHoneypots(honeypotsData);
      setCheckpoints(checkpointsData);
      setMilestones(milestonesData);
    } catch (err) {
      console.error('Failed to load initial data:', err);
    }
  };

  useEffect(() => {
    loadAllData();
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws/stream`);

    socket.onopen = () => setIsConnected(true);
    socket.onclose = () => setIsConnected(false);

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event === 'INTERCEPTION') {
          const decision = msg.data as InterceptionDecision;
          setInterceptions((prev) => [decision, ...prev.slice(0, 49)]);
          setSelectedInterception(decision);
          if (decision.honeypot_triggered) {
            showToast('DECEPTION TRIPWIRE BREACH', `Canary token touched by ${decision.agent_id}! Agent quarantined.`, 'alert');
          } else if (decision.decision === 'BLOCK') {
            showToast('INVOCATION BLOCKED', `Pre-execution aborted for ${decision.tool_name} (${decision.agent_id}).`, 'alert');
          }
          api.getStats().then(setStats);
          api.getLedger(50).then(setLedgerBlocks);
          api.getAgents().then(setAgents);
          api.getApprovals().then(setApprovals);
        } else if (msg.event === 'AGENT_STATE_CHANGE') {
          api.getAgents().then(setAgents);
          api.getStats().then(setStats);
        } else if (msg.event === 'APPROVAL_RESOLVED') {
          api.getApprovals().then(setApprovals);
          api.getStats().then(setStats);
          api.getLedger(50).then(setLedgerBlocks);
          showToast('APPROVAL RESOLVED', `Action updated: ${msg.data.status}`, 'success');
        } else if (msg.event === 'CHECKPOINT_CREATED') {
          api.getCheckpoints().then(setCheckpoints);
        }
      } catch (err) { /* ignore */ }
    };

    wsRef.current = socket;
    return () => socket.close();
  }, []);

  // Polling fallback
  useEffect(() => {
    const interval = setInterval(() => {
      api.getStats().then(setStats).catch(() => {});
      api.getApprovals().then(setApprovals).catch(() => {});
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  // Swarm traffic generator
  useEffect(() => {
    if (!isTrafficGenerating) return;
    const interval = setInterval(async () => {
      try {
        await api.simulateTraffic();
        const [s, l, ag, ap, inc] = await Promise.all([
          api.getStats(), api.getLedger(50), api.getAgents(), api.getApprovals(), api.getInterceptions(50)
        ]);
        setStats(s); setLedgerBlocks(l); setAgents(ag); setApprovals(ap); setInterceptions(inc);
      } catch (err) { /* ignore */ }
    }, 4500);
    return () => clearInterval(interval);
  }, [isTrafficGenerating]);

  // ── TAB SCAN CONTENT OVERLAY — sweeps 0→100% vertically on tab switch ──
  const handleSetActiveTab = (tab: DashboardTab) => {
    // Clear any existing scan
    if (contentScanRef.current) clearInterval(contentScanRef.current);

    setIsContentScanning(true);
    setContentScanProgress(0);

    let progress = 0;
    const tick = setInterval(() => {
      // Fast ease-in: starts slow, accelerates, slows at end
      const t = progress / 100;
      const eased = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
      const increment = Math.max(2, (1 - eased) * 8 + Math.random() * 5);
      progress = Math.min(100, progress + increment);
      setContentScanProgress(Math.round(progress));

      if (progress >= 100) {
        clearInterval(tick);
        contentScanRef.current = null;
        // Slight delay then reveal
        setTimeout(() => {
          setActiveTab(tab);
          setIsContentScanning(false);
          setContentScanProgress(0);
        }, 80);
      }
    }, 20);

    contentScanRef.current = tick;
  };

  useEffect(() => {
    return () => { if (contentScanRef.current) clearInterval(contentScanRef.current); };
  }, []);

  // Handlers
  const handleSimulate = async (payload: {
    agent_id: string;
    tool_name: string;
    arguments: Record<string, unknown>;
    task_id: string;
    trace_id: string;
    token_epoch?: number;
  }) => {
    setIsSimulating(true);
    try {
      const decision = await api.authorize(payload);
      setSelectedInterception(decision);
      setInterceptions((prev) => [decision, ...prev.slice(0, 49)]);
      const [s, l, ag, ap] = await Promise.all([api.getStats(), api.getLedger(50), api.getAgents(), api.getApprovals()]);
      setStats(s); setLedgerBlocks(l); setAgents(ag); setApprovals(ap);
      showToast('PROPOSAL EVALUATED', `Gateway Decision: ${decision.decision}`, decision.decision === 'BLOCK' ? 'alert' : 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('SIMULATION ERROR', msg, 'alert');
    } finally { setIsSimulating(false); }
  };

  const handleQuarantineAgent = async (agentId: string) => {
    try {
      await api.quarantineAgent(agentId, 'Manual Security Analyst Quarantine');
      setAgents(await api.getAgents());
      api.getStats().then(setStats);
      showToast('AGENT QUARANTINED', `${agentId} placed under strict quarantine.`, 'alert');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('QUARANTINE NOTICE', msg, 'alert');
    }
  };

  const handleResetAgent = async (agentId: string) => {
    try {
      await api.resetAgent(agentId);
      setAgents(await api.getAgents());
      api.getStats().then(setStats);
      showToast('AGENT RESET', `${agentId} restored to HEALTHY status.`, 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('RESET NOTICE', msg, 'alert');
    }
  };

  const handleBumpEpoch = async (agentId: string) => {
    try {
      const res = await api.bumpAgentEpoch(agentId);
      setAgents(await api.getAgents());
      showToast('EPOCH BUMPED', `${agentId} bumped to Epoch v${res.new_epoch}. Tokens invalidated.`, 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('BUMP EPOCH ERROR', msg, 'alert');
    }
  };

  const handleResolveApproval = async (approvalId: string, action: 'APPROVE' | 'REJECT', note: string) => {
    try {
      const res = await api.resolveApproval(approvalId, action, note);
      const [ap, l, s, inc] = await Promise.all([
        api.getApprovals(), api.getLedger(50), api.getStats(), api.getInterceptions(50)
      ]);
      setApprovals(ap); setLedgerBlocks(l); setStats(s); setInterceptions(inc);
      showToast(action === 'APPROVE' ? 'EXECUTION APPROVED' : 'EXECUTION REJECTED', `Approval ${approvalId}: ${res.status}`, 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('RESOLVE ERROR', msg, 'alert');
    }
  };

  const handleVerifyLedger = async () => {
    setIsVerifyingLedger(true);
    try {
      const result = await api.verifyLedgerIntegrity();
      setLedgerVerification(result);
      showToast('LEDGER AUDIT COMPLETE', result.valid ? 'Merkle chain cryptographically verified.' : 'Verification check finished.', 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('VERIFY ERROR', msg, 'alert');
    } finally { setIsVerifyingLedger(false); }
  };

  const handleReplayScenario = async (scenarioId: string) => {
    setIsReplaying(true);
    try {
      const res = await api.replayScenario(scenarioId);
      setReplayResult(res);
      const [s, l, i] = await Promise.all([api.getStats(), api.getLedger(50), api.getInterceptions(50)]);
      setStats(s); setLedgerBlocks(l); setInterceptions(i);
      showToast('COUNTERFACTUAL REPLAY', `Scenario ${scenarioId} replayed deterministically.`, 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('REPLAY ERROR', msg, 'alert');
    } finally { setIsReplaying(false); }
  };

  const handleRunAttackScenario = async (scenarioId: string) => {
    try {
      const res = await api.replayScenario(scenarioId);
      const [s, l, i, ag, ap] = await Promise.all([
        api.getStats(), api.getLedger(50), api.getInterceptions(50), api.getAgents(), api.getApprovals()
      ]);
      setStats(s); setLedgerBlocks(l); setInterceptions(i); setAgents(ag); setApprovals(ap);
      showToast('ATTACK SCENARIO EXECUTED', `${scenarioId} -> Decision: ${res.decision.decision}`, res.decision.decision === 'BLOCK' ? 'alert' : 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('SCENARIO RUN NOTICE', msg, 'alert');
    }
  };

  const handleCreateCheckpoint = async (name: string, description: string) => {
    try {
      await api.createCheckpoint(name, description);
      setCheckpoints(await api.getCheckpoints());
      showToast('SNAPSHOT CREATED', `System ledger checkpoint "${name}" committed.`, 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('CHECKPOINT ERROR', msg, 'alert');
    }
  };

  const handleRunMilestones = async () => {
    setIsRunningMilestones(true);
    try {
      setMilestones(await api.runMilestones());
      showToast('INVARIANT MILESTONES VERIFIED', 'All P0 security compliance invariants checked.', 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('MILESTONES ERROR', msg, 'alert');
    } finally { setIsRunningMilestones(false); }
  };

  const handleResetDemo = async () => {
    setIsResetting(true);
    try {
      await api.resetDemo();
      await loadAllData();
      showToast('DEMO RESET', 'Pristine initial Gateway state restored.', 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('RESET ERROR', msg, 'alert');
    } finally {
      setIsResetting(false);
    }
  };

  const handleToggleTraffic = () => {
    setIsTrafficGenerating((prev) => !prev);
    if (!isTrafficGenerating) {
      showToast('TRAFFIC GENERATOR ACTIVE', 'Autonomous agent proposal swarm started.', 'success');
    } else {
      showToast('TRAFFIC PAUSED', 'Traffic generator stopped.', 'success');
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#F5F0E8] text-[#1E232A] relative">

      {/* Toast stack */}
      <div className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2 items-end">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            title={toast.title}
            message={toast.message}
            type={toast.type}
            onClose={() => setToasts((prev) => prev.filter((t) => t.id !== toast.id))}
          />
        ))}
      </div>

      {/* Navbar — passes handleSetActiveTab for scan-then-switch behavior */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={handleSetActiveTab}
        isConnected={isConnected}
        ledgerHeight={stats?.ledger_height ?? 0}
        isTrafficGenerating={isTrafficGenerating}
        onToggleTraffic={handleToggleTraffic}
        onResetDemo={handleResetDemo}
        isResetting={isResetting}
      />

      {/* Main Container */}
      <main className="flex-1 w-full max-w-[1720px] mx-auto px-3 sm:px-5 py-4 space-y-4 relative">

        {/* ── CONTENT SCAN OVERLAY — vertical beam sweep 0→100% ── */}
        {isContentScanning && (
          <div className="absolute inset-0 z-30 pointer-events-none overflow-hidden rounded-xl">
            {/* Dimming layer that reveals from top */}
            <div
              className="absolute inset-0 bg-[#F5F0E8]"
              style={{
                clipPath: `inset(${contentScanProgress}% 0 0 0)`,
                transition: 'clip-path 0.02s linear',
              }}
            />
            {/* Glowing scan beam */}
            <div
              className="absolute left-0 right-0 h-1 pointer-events-none"
              style={{
                top: `${contentScanProgress}%`,
                background: 'linear-gradient(90deg, transparent 0%, #0E7490 20%, #047857 50%, #6D28D9 80%, transparent 100%)',
                boxShadow: '0 0 20px 4px rgba(14,116,144,0.4), 0 0 40px 8px rgba(4,120,87,0.2)',
                transition: 'top 0.02s linear',
              }}
            />
            {/* Scan progress indicator */}
            <div className="absolute top-4 right-4 flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#EDE8DE] border border-[#D6CFC3] text-[11px] font-mono font-bold text-[#0E7490] shadow-md">
              <span className="w-2 h-2 rounded-full bg-[#047857] animate-pulse" />
              SCANNING {contentScanProgress}%
            </div>
          </div>
        )}

        <div key={activeTab} className="tab-enter">
          {activeTab === 'realtime-ecosystem' && (
            <RealtimeEcosystemView
              interceptions={interceptions}
              agents={agents}
              approvals={approvals}
              ledgerBlocks={ledgerBlocks}
              onSelectInterception={setDrawerDecision}
              onQuarantineAgent={handleQuarantineAgent}
              onResetAgent={handleResetAgent}
              onBumpEpoch={handleBumpEpoch}
              onResolveApproval={handleResolveApproval}
              onRunAttackScenario={handleRunAttackScenario}
            />
          )}
          {activeTab === 'advanced-security' && (
            <PipelineDeepDiveView
              currentDecision={selectedInterception}
              onSimulate={handleSimulate}
              isSimulating={isSimulating}
            />
          )}
          {activeTab === 'simulation-lab' && (
            <AttackLabView
              scenarios={scenarios}
              honeypots={honeypots}
              onReplayScenario={handleReplayScenario}
              isReplaying={isReplaying}
              replayResult={replayResult}
            />
          )}
          {activeTab === 'orchestration-audit' && (
            <CheckpointsView
              checkpoints={checkpoints}
              milestones={milestones}
              onCreateCheckpoint={handleCreateCheckpoint}
              onRunMilestones={handleRunMilestones}
              isRunningMilestones={isRunningMilestones}
              ledgerBlocks={ledgerBlocks}
            />
          )}
          {activeTab === 'runtime-integrity' && (
            <RuntimeIntegrityView
              agents={agents}
              interceptions={interceptions}
              approvals={approvals}
              ledgerBlocks={ledgerBlocks}
              onQuarantineAgent={handleQuarantineAgent}
              onResetAgent={handleResetAgent}
              onBumpEpoch={handleBumpEpoch}
            />
          )}
        </div>
      </main>

      {/* Event Detail Drawer */}
      <EventDetailDrawer decision={drawerDecision} onClose={() => setDrawerDecision(null)} />
    </div>
  );
}


export default App;
