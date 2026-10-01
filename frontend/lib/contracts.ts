/**
 * Generated TypeScript API contracts directly aligned with AgentGuard OpenAPI specification.
 * DO NOT manually modify field names or enum constants.
 */

export type DecisionOutcome = "ALLOW" | "WARN" | "REQUIRE_APPROVAL" | "BLOCK";

export type ExecutionState =
  | "REQUESTED"
  | "AUTHORIZED"
  | "BLOCKED"
  | "APPROVAL_PENDING"
  | "APPROVED"
  | "EXECUTING"
  | "SUCCEEDED"
  | "FAILED"
  | "CANCELLED"
  | "UNKNOWN_RESULT";

export type ReasonCode =
  | "AGENT_DISABLED"
  | "AGENT_QUARANTINED"
  | "CAPABILITY_DENIED"
  | "TOOL_UNREGISTERED"
  | "SCHEMA_INVALID"
  | "PATH_TRAVERSAL"
  | "SENSITIVE_RESOURCE"
  | "DESTINATION_NOT_ALLOWLISTED"
  | "TASK_INCONSISTENT"
  | "COMM_PATH_DENIED"
  | "HONEY_ASSET_TOUCHED"
  | "CUMULATIVE_RISK_HIGH"
  | "BREAKER_TRIPPED"
  | "REQUEST_REPLAYED"
  | "TOKEN_INVALID"
  | "APPROVAL_STALE"
  | "EXECUTION_DUPLICATE"
  | "RESULT_UNKNOWN";

export interface Reason {
  code: ReasonCode;
  message: string;
  severity: string;
  source: string;
}

export interface Decision {
  decision: DecisionOutcome;
  agent_id: string;
  tool_name: string;
  task_id: string;
  trace_id: string;
  execution_id: string;
  reasons: Reason[];
  risk?: {
    score: number;
    factors: Record<string, number>;
  };
  parameter_result?: Record<string, any>;
  policy_results?: Record<string, any>;
  capability_result?: Record<string, any>;
}

export interface AgentInfo {
  agent_id: string;
  name: string;
  status: "active" | "paused" | "disabled" | "suspended" | "retired";
  security_state: "CLEAN" | "TRUSTED" | "SUSPECTED" | "COMPROMISED" | "QUARANTINED" | "RECOVERED";
  capability_version: string;
  task_id: string;
  security_epoch: number;
  allowed_tools: string[];
  scopes: string[];
}

export interface ToolInfo {
  tool_name: string;
  version: string;
  description: string;
  required_capability: string;
  enabled: boolean;
}

export interface ApprovalRecord {
  approval_id: string;
  status: "APPROVAL_PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "STALE";
  expires_at: number;
  fields?: Record<string, any>;
}

export interface IncidentRecord {
  incident_id: string;
  agent_id: string;
  task_id: string;
  trace_id: string;
  reason_code: string;
  severity: string;
  state: "DETECTED" | "ANALYZED" | "CONTAINED" | "RESOLVED";
  created_at: number;
}

export interface GraphData {
  nodes: Array<{ id: string; type: string; label: string; [key: string]: any }>;
  edges: Array<{ source: string; target: string; relationship: string; [key: string]: any }>;
}

export interface AuditVerification {
  verified: boolean;
  checked_events: number;
  error?: string | null;
}
