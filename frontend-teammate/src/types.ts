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

export interface DemoScenarioInfo {
  id: string;
  name: string;
  description: string;
  expected_decision: string;
}

export interface DemoResourceItem {
  id: string;
  name: string;
  path: string;
  classification: string;
  access: string;
  description: string;
  size_bytes: number;
}

export interface DemoDatabaseItem {
  table_name: string;
  classification: string;
  description: string;
  row_count: number;
}

export interface DemoEnvironmentData {
  agent: {
    agent_id: string;
    name: string;
    status: string;
    task_id: string;
    security_epoch: number;
    security_state: string;
    allowed_tools: string[];
  };
  scenarios: DemoScenarioInfo[];
  resources: DemoResourceItem[];
  database: DemoDatabaseItem[];
}

export interface DemoScenarioResult {
  scenario_id: string;
  trace_id: string;
  decision: string;
  tool_name: string;
  target_resource: string;
  reasons: string[];
  explanation: string;
  execution_status: string;
  executions_count: number;
  agent_quarantined: boolean;
  output_preview?: string | null;
}

// ── Real-Time Threat Intelligence & Benchmark Contracts ──

export interface ProviderHealthItem {
  provider_name: string;
  display_name: string;
  status: 'online' | 'no_key' | 'degraded' | 'offline';
  has_api_key: boolean;
  total_queries: number;
  successful_queries: number;
  failed_queries: number;
  avg_latency_ms: number;
  last_queried_at?: string | null;
  last_error?: string | null;
  supported_types: string[];
  is_free_tier: boolean;
  rate_limit_info?: string | null;
}

export interface ProviderResultItem {
  provider_name: string;
  indicator: string;
  indicator_type: string;
  reputation: 'benign' | 'suspicious' | 'malicious' | 'unknown';
  risk_score: number;
  confidence: number;
  details: Record<string, unknown>;
  raw_data?: Record<string, unknown> | null;
  source_url?: string | null;
  queried_at: string;
  latency_ms: number;
  error?: string | null;
}

export interface EnrichedIndicatorItem {
  indicator: string;
  indicator_type: string;
  overall_reputation: 'benign' | 'suspicious' | 'malicious' | 'unknown';
  overall_risk_score: number;
  max_confidence: number;
  provider_results: ProviderResultItem[];
  primary_provider?: string | null;
  cached: boolean;
  tags: string[];
  summary: string;
  extracted_from?: string | null;
  timestamp?: string;
}

export interface BenchmarkScenarioItem {
  id: string;
  name: string;
  category: string;
  description: string;
  agent_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  expected_outcome: string;
  threat_profile: string;
}

export interface BenchmarkScenarioExecutionResult {
  scenario: BenchmarkScenarioItem;
  actual_decision: string;
  expected_decision: string;
  decision_matched: boolean;
  latency_ms: number;
  risk_score: number;
  reasons: string[];
  threat_details: Array<Record<string, unknown>>;
  executed_at: string;
}

export interface LatencyPercentiles {
  avg: number;
  min: number;
  max: number;
  p50: number;
  p95: number;
  p99: number;
}

export interface LiveBenchmarkMetrics {
  timestamp: string;
  uptime_seconds: number;
  total_events_evaluated: number;
  decisions: {
    ALLOW: number;
    WARN: number;
    REQUIRE_APPROVAL: number;
    BLOCK: number;
  };
  gateway_latency_ms: LatencyPercentiles;
  threat_intel_latency_ms: LatencyPercentiles;
  throughput_events_per_sec: number;
  threat_intel_stats: {
    total_indicators_enriched: number;
    total_lookups?: number;
    cache_hits: number;
    cache_misses: number;
    cache_hit_rate_pct: number;
    active_providers_count: number;
    total_providers: number;
  };
  active_benchmark_running: boolean;
  current_benchmark?: Record<string, unknown> | null;
}

export interface BenchmarkEventItem {
  id: string;
  timestamp: string;
  agent_id: string;
  tool_name: string;
  outcome: string;
  gateway_latency_ms: number;
  threat_latency_ms: number;
  threat_indicators_count: number;
  threat_intel_details: Array<Record<string, unknown>>;
  reasons: string[];
  risk_score: number;
}
