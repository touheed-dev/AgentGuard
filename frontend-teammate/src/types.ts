export type DecisionType = 'ALLOW' | 'WARN' | 'REQUIRE_APPROVAL' | 'BLOCK';
export type AgentStatus = 'HEALTHY' | 'SUSPICIOUS' | 'QUARANTINED' | 'REVOKED';
export type StageStatus = 'PASS' | 'ALLOW' | 'WARN' | 'REQUIRE_APPROVAL' | 'BLOCK' | 'SHORT_CIRCUIT';

export interface StageResult {
  stage_num: number;
  stage_name: string;
  status: StageStatus;
  latency_us: number;
  rule_matched?: string;
  detail: string;
  evidence?: Record<string, unknown> | null;
}

export interface InterceptionDecision {
  decision: DecisionType;
  agent_id: string;
  tool_name: string;
  task_id: string;
  trace_id: string;
  risk_score: number;
  timestamp: number;
  canonical_hash: string;
  block_index?: number;
  stage_results: StageResult[];
  redacted_arguments: Record<string, unknown>;
  requires_approval: boolean;
  approval_id?: string;
  post_block_executed: boolean;
  honeypot_triggered: boolean;
  circuit_breaker_status: AgentStatus;
}

export interface AgentRecord {
  agent_id: string;
  name: string;
  role: string;
  allowed_tools: string[];
  status: AgentStatus;
  security_epoch: number;
  created_at: number;
  active_violations_60s: number;
  quarantine_reason?: string;
  total_interceptions: number;
  blocked_count: number;
  allowed_count: number;
  approval_count: number;
}

export interface ApprovalItem {
  approval_id: string;
  trace_id: string;
  task_id: string;
  agent_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  redacted_arguments: Record<string, unknown>;
  risk_score: number;
  freshness_fingerprint: string;
  created_at: number;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'INVALIDATED';
  decision_reason: string;
}

export interface LedgerBlock {
  block_index: number;
  timestamp: number;
  prev_hash: string;
  merkle_root: string;
  state_hash: string;
  canonical_payload: string;
  event_type: string;
  agent_id: string;
  tool_name: string;
  decision: DecisionType;
  risk_score: number;
  block_hash: string;
}

export interface DagNode {
  id: string;
  label: string;
  agent_id: string;
  tool_name: string;
  status: string;
  risk: number;
  step: number;
  args: Record<string, unknown>;
}

export interface ScenarioFixture {
  scenario_id: string;
  title: string;
  category: string;
  mitre_technique: string;
  description: string;
  dag_nodes: DagNode[];
  test_request: {
    agent_id: string;
    tool_name: string;
    arguments: Record<string, unknown>;
    task_id: string;
    trace_id: string;
    token_epoch?: number;
  };
  expected_decision: string;
  failing_stage?: number;
  failing_stage_name?: string;
}

export interface CheckpointSnapshot {
  checkpoint_id: string;
  name: string;
  timestamp: number;
  ledger_height: number;
  ledger_head_hash: string;
  total_interceptions: number;
  quarantined_agents_count: number;
  pending_approvals_count: number;
  policy_epoch: number;
  state_signature: string;
  description: string;
}

export interface MilestoneResult {
  milestone_id: string;
  title: string;
  target_requirement: string;
  status: 'VERIFIED' | 'FAILED';
  verified_at: number;
  details: string;
  metrics: Record<string, unknown>;
}

export interface GatewayStats {
  post_block_execution_rate: string;
  total_intercepted: number;
  blocked_count: number;
  allowed_count: number;
  warn_count: number;
  pending_approvals_count: number;
  total_agents: number;
  quarantined_agents_count: number;
  ledger_height: number;
  ledger_head_hash: string;
  policy_epoch: number;
  gateway_public_key: string;
}

export interface HoneypotAsset {
  token: string;
  category: string;
  type: string;
  status: string;
  action_on_touch: string;
}

export interface LedgerVerificationResult {
  valid: boolean;
  verified_blocks: number;
  standard: string;
  error?: string | null;
}

export interface ScenarioReplayResult {
  scenario_id: string;
  scenario_name: string;
  expected: string;
  actual: string;
  deterministic_match: boolean;
  decision: InterceptionDecision;
  reasons: string[];
  agent_security_state: string;
  agent_status: string;
  executed: boolean;
}

export interface DemoResourceItem {
  id: string;
  name: string;
  path: string;
  classification: 'PUBLIC' | 'UNTRUSTED' | 'RESTRICTED' | 'HONEY_ASSET';
  access: string;
  description: string;
  size_bytes: number;
}

export interface DemoDatabaseTable {
  table_name: string;
  classification: 'PUBLIC' | 'RESTRICTED' | 'SENSITIVE' | 'ALLOWED';
  row_count: number;
  description: string;
}

export interface DemoScenarioInfo {
  id: string;
  name: string;
  description: string;
  target: string;
  expected_decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_APPROVAL' | 'BLOCK + QUARANTINE';
  risk_level: 'LOW' | 'HIGH' | 'CRITICAL';
}

export interface DemoEnvironmentData {
  agent: {
    agent_id: string;
    name: string;
    status: string;
    security_state: string;
    task_id: string;
    security_epoch: number;
    allowed_tools: string[];
  };
  resources: DemoResourceItem[];
  database: DemoDatabaseTable[];
  scenarios: DemoScenarioInfo[];
  execution_stats: {
    total_executions: number;
    post_block_rate: string;
  };
}

export interface DemoScenarioResult {
  scenario_id: string;
  scenario_name: string;
  agent_id: string;
  tool_name: string;
  target_resource: string;
  decision: DecisionType;
  reasons: string[];
  risk_score: number;
  execution_status: string;
  executions_count: number;
  trace_id: string;
  output_preview?: string | null;
  explanation: string;
  agent_quarantined: boolean;
  approval_id?: string | null;
}

