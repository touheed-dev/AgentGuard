import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { KpiTiles } from './components/KpiTiles';
import { CommandCenterView } from './components/CommandCenterView';
import { PipelineDeepDiveView } from './components/PipelineDeepDiveView';
import { AttackLabView } from './components/AttackLabView';
import { CheckpointsView } from './components/CheckpointsView';
import { TelemetryChart } from './components/TelemetryChart';
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
    <div className={`anim-fade-up flex items-start gap-3 px-4 py-3 rounded-2xl border shadow-2xl max-w-sm w-full ${
      isAlert
        ? 'bg-red-950/90 border-red-800/60 text-red-100 shadow-red-950/50'
        : 'bg-emerald-950/90 border-emerald-800/60 text-emerald-100 shadow-emerald-950/50'
    }`} style={{ backdropFilter: 'blur(16px)' }}>
      <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
        isAlert ? 'bg-red-900/60' : 'bg-emerald-900/60'
      }`}>
        {isAlert
          ? <ShieldAlert className="w-4 h-4 text-red-400" />
          : <CheckCircle className="w-4 h-4 text-emerald-400" />
        }
      </div>
      <div className="flex-1 min-w-0">
        <div className="font-bold text-[10px] font-mono uppercase tracking-widest mb-0.5 opacity-80">{title}</div>
        <div className="text-xs text-slate-300">{message}</div>
      </div>
      <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors ml-1">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

export function App() {
  type Tab = 'command-center' | 'pipeline' | 'attack-lab' | 'checkpoints';
  const [activeTab, setActiveTab] = useState<Tab>('command-center');
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
  const [drawerDecision, setDrawerDecision] = useState<InterceptionDecision | null>(null);
  const [toasts, setToasts] = useState<Array<{ id: string; title: string; message: string; type: 'alert' | 'success' }>>([]);

  const wsRef = useRef<WebSocket | null>(null);

  const showToast = (title: string, message: string, type: 'alert' | 'success' = 'alert') => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev.slice(-2), { id, title, message, type }]);
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
            showToast('🍯 DECEPTION TRIPWIRE BREACH', `Canary token touched by ${decision.agent_id}! Agent quarantined.`, 'alert');
          } else if (decision.decision === 'BLOCK') {
            showToast('🛑 INVOCATION BLOCKED', `Pre-execution aborted for ${decision.tool_name} (${decision.agent_id}).`, 'alert');
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
      try { await api.simulateTraffic(); } catch (err) { /* ignore */ }
    }, 4500);
    return () => clearInterval(interval);
  }, [isTrafficGenerating]);

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
      const [ap, l, s] = await Promise.all([api.getApprovals(), api.getLedger(50), api.getStats()]);
      setApprovals(ap); setLedgerBlocks(l); setStats(s);
      showToast(action === 'APPROVE' ? 'EXECUTION APPROVED' : 'EXECUTION REJECTED', `Approval ${approvalId}: ${res.status}`, 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('RESOLVE ERROR', msg, 'alert');
    }
  };

  const handleVerifyLedger = async () => {
    setIsVerifyingLedger(true);
    try {
      setLedgerVerification(await api.verifyLedgerIntegrity());
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
      if (res.decision) setSelectedInterception(res.decision);
      showToast(
        res.deterministic_match ? '✅ DETERMINISTIC MATCH' : '⚠️ MISMATCH',
        `${scenarioId}: Expected ${res.expected}, got ${res.actual}`,
        res.deterministic_match ? 'success' : 'alert'
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('REPLAY ERROR', msg, 'alert');
    } finally { setIsReplaying(false); }
  };

  const handleCreateCheckpoint = async (name: string, description: string) => {
    const ckpt = await api.createCheckpoint(name, description);
    setCheckpoints((prev) => [ckpt, ...prev]);
    showToast('CHECKPOINT SAVED', `Snapshot ${ckpt.checkpoint_id} committed at ledger #${ckpt.ledger_height}.`, 'success');
  };

  const handleRunMilestones = async () => {
    setIsRunningMilestones(true);
    try {
      setMilestones(await api.runMilestones());
      showToast('MILESTONES VERIFIED', 'All security invariants M1–M5 evaluated.', 'success');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      showToast('MILESTONE ERROR', msg, 'alert');
    } finally { setIsRunningMilestones(false); }
  };

  const [isResetting, setIsResetting] = useState(false);

  const handleResetDemo = async () => {
    setIsResetting(true);
    try {
      await api.resetDemo();
      await loadAllData();
      showToast('DEMO RESET COMPLETE', 'Gateway, agents, circuit breakers, and trace graph restored to pristine state.', 'success');
    } catch (err) {
      showToast('DEMO RESET ERROR', err instanceof Error ? err.message : 'Failed to reset demo state', 'alert');
    } finally {
      setIsResetting(false);
    }
  };

  const handleToggleTraffic = () => {
    setIsTrafficGenerating((prev) => !prev);
    if (!isTrafficGenerating) {
      showToast('SWARM TRAFFIC ACTIVE', 'Continuous agent mesh tool calls started.', 'success');
    } else {
      showToast('TRAFFIC PAUSED', 'Traffic generator stopped.', 'success');
    }
  };

  return (
    <div className="min-h-screen flex flex-col" style={{ background: '#F5F0E8' }}>

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

      {/* Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        isConnected={isConnected}
        ledgerHeight={stats?.ledger_height ?? 0}
        isTrafficGenerating={isTrafficGenerating}
        onToggleTraffic={handleToggleTraffic}
        onResetDemo={handleResetDemo}
        isResetting={isResetting}
      />

      {/* Main */}
      <main className="flex-1 w-full max-w-screen-2xl mx-auto px-4 md:px-6 py-5 space-y-4">
        <KpiTiles stats={stats} />
        <TelemetryChart
          interceptions={interceptions}
          agents={agents}
          isTrafficGenerating={isTrafficGenerating}
          onToggleTraffic={handleToggleTraffic}
        />

        <div key={activeTab} className="tab-enter">
          {activeTab === 'command-center' && (
            <CommandCenterView
              interceptions={interceptions}
              agents={agents}
              approvals={approvals}
              ledgerBlocks={ledgerBlocks}
              onSelectInterception={setDrawerDecision}
              onQuarantineAgent={handleQuarantineAgent}
              onResetAgent={handleResetAgent}
              onBumpEpoch={handleBumpEpoch}
              onResolveApproval={handleResolveApproval}
              onVerifyLedger={handleVerifyLedger}
              ledgerVerification={ledgerVerification}
              isVerifyingLedger={isVerifyingLedger}
            />
          )}
          {activeTab === 'pipeline' && (
            <PipelineDeepDiveView
              currentDecision={selectedInterception}
              onSimulate={handleSimulate}
              isSimulating={isSimulating}
            />
          )}
          {activeTab === 'attack-lab' && (
            <AttackLabView
              scenarios={scenarios}
              honeypots={honeypots}
              onReplayScenario={handleReplayScenario}
              isReplaying={isReplaying}
              replayResult={replayResult}
            />
          )}
          {activeTab === 'checkpoints' && (
            <CheckpointsView
              checkpoints={checkpoints}
              milestones={milestones}
              onCreateCheckpoint={handleCreateCheckpoint}
              onRunMilestones={handleRunMilestones}
              isRunningMilestones={isRunningMilestones}
            />
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-[#DDD8CE] bg-[#EDE8DE]/80 py-3 px-6">
        <div className="max-w-screen-2xl mx-auto flex flex-wrap items-center justify-between gap-3 text-[10px] font-mono text-slate-700">
          <span>AgentGuard Runtime Security Gateway • Fail-Closed Invariant</span>
          <div className="flex items-center gap-4">
            <span>RFC-8785 SHA-256</span>
            <span>•</span>
            <span>POST-BLOCK RATE: <span className="text-emerald-600">0.00%</span></span>
            <span>•</span>
            <span>PUBKEY: {stats?.gateway_public_key ?? 'ed25519:…'}</span>
          </div>
        </div>
      </footer>

      {/* Event Detail Drawer */}
      <EventDetailDrawer decision={drawerDecision} onClose={() => setDrawerDecision(null)} />
    </div>
  );
}

export default App;
