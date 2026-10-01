# AgentGuard — Product Requirements Document (v2)

**Owner:** Team Nexify | **Status:** v2.4.1 (architecture lock; further changes via ADRs, versioned schemas and test-backed pull requests) | **Changes from v1:** modular-monolith architecture, free-only technology stack, no fixed deadline (sequenced by dependency, not by calendar), Groq as the default live-mode LLM with Ollama optional and replay mandatory, plus security-semantics corrections (redacted approvals, normative Gateway order, reason codes, policy precedence, token claims, exact hash-chain format), approval freshness, execution idempotency, sandbox limits and a corrected roadmap

---

## 1. Overview

AgentGuard is a runtime security and integrity layer between autonomous AI agents and everything they can touch (tools, APIs, files, databases, code execution, other agents). Every action is intercepted and evaluated **before execution** and resolved to `ALLOW`, `WARN`, `REQUIRE_APPROVAL`, or `BLOCK`, with an explanation.

> *Other projects build autonomous agents. AgentGuard controls what those agents are allowed to do.*

**It is not:** an agent, a chatbot, a prompt-injection classifier, or an activity logger.

AgentGuard does not decide whether an agent is intelligent or trustworthy. It decides whether a requested action is authorized, safe enough, explainable, and executable in the current context.

## 2. Problem

Agents call tools, read untrusted content, run code and delegate work with little runtime oversight. Most harmful actions are *technically executable*: the tool exists and the credentials are reachable. Executability is not authorization.

Failure modes: unauthorized tool use, secret access, unsafe code execution, data exfiltration, unknown-agent contact, privilege escalation, task deviation, retry/probing abuse, prompt injection, security-control bypass.

Why existing approaches fall short: prompt instructions are unenforceable; API-key scoping is static; logging is after the fact; LLM classifiers are probabilistic; human RBAC isn't built for self-directed callers; sandboxing protects the host but not data or outbound calls.

## 3. Goals and Non-Goals

**Goals**

1. One explainable, pre-execution decision per action, using identity, capability, parameters, task consistency, behavior, and cumulative risk.
2. No path from an agent to the outside world that bypasses the Gateway.
3. Automatic containment of compromised agents, with a tamper-evident, replayable record.
4. A stack that is **entirely free to build, run and demo**. Live mode uses a free Groq key; replay mode needs no key or network, so no paid or networked service sits on the critical path.
5. A first release that grows into the platform without a rewrite.

**Non-Goals (initial release)**

- Proving an agent is safe (the product prevents defined classes of unsafe behavior only).
- ML anomaly detection, multi-tenancy, SSO at scale, Kubernetes, distributed gateways, threat intel, automated remediation.
- Letting an LLM be the sole decider of any block (hard rule).

## 4. Users

| User | Need |
| --- | --- |
| Security / platform engineer | Define roles, tools, policies; investigate incidents |
| Human approver | Approve or reject high-impact actions with full context |
| Agent developer | Register agents/tools; route calls through `authorize()` |
| Evaluator / judge | Understand what happened, why, and what would have happened without AgentGuard |

## 5. Principles

Least privilege · deny by default · defense in depth · zero-trust between agents · fail closed for critical tools · every decision explained · policy separate from execution · risk score augments policy and never overrides a hard rule · trust score is a signal, never a gate · deterministic decisions, no LLM in the decision path.

## 6. Scope and Priority

Priority order (a lower item never displaces a higher one): 1 Runtime interception · 2 Identity/capability · 3 Policy engine · 4 Parameter validation · 5 Risk engine · 6 Prompt-injection attack demo · 7 Circuit breaker · 8 Audit logging · 9 Incident system · 10 Human approval · 11 Trace replay · 12 Dashboard · 13 Advanced analytics · 14 Extra attack scenarios · 15 Platform features.

| Tier | Contents |
| --- | --- |
| **P0 — Core** | Gateway, registries, identity/capability, policy, parameter validation, task consistency, risk, decision, circuit breaker, human approval, hash-chained audit, incidents, traces, 4 agents (Planner, Researcher, Coder, Executor), prompt-injection attack, 1 HoneyTool, 1 Honeytoken, quarantine, attack-chain graph, trace replay, dashboard (6 core views), attack lab (6 scenarios), scripted-replay agent mode |
| **P1 — Differentiators** | Reviewer agent, HoneyAgent, Agent Twin, counterfactual mode, policy mutation, Attack Director, Protection Score, remaining dashboard views, full 15-scenario attack lab, Audit Integrity UI, signed audit checkpoints |
| **P2 — Platform** | Behavioral/ML anomaly detection, adaptive trust, framework adapters (LangGraph, CrewAI, AutoGen), MCP proxy, OIDC SSO, multi-tenancy, gVisor/Firecracker hardening, distributed gateways, Kubernetes, threat intel, automated response |

**P0 feature classes** (if a demo feature threatens the kernel, defer the demo feature):

| Class | Meaning | Contents |
| --- | --- | --- |
| P0 kernel | Must work correctly | Gateway, identity, capability, tool registry, policy, parameter validation, decision engine, audit, request and execution idempotency, circuit breaker, approval state machine, tool execution boundary |
| P0 demo | Must be visible | Four agents, legitimate ALLOW flow, one real approval, prompt injection, HoneyTool, Honeytoken, quarantine, attack graph, replay |
| P0 support | May be basic | Six dashboard views, basic task consistency, six attack scenarios, basic risk scoring, basic communication graph |

With no fixed deadline, P0 → P1 → P2 are built in order. Each stage must leave a runnable, demoable system.

## 7. Functional Requirements

### FR-1 Gateway and interception (P0)

- All actions, including agent-to-agent messages and delegations, pass through `authorize(agent_id, tool_name, arguments, task_id, trace_id) -> Decision`.
- Authorization always occurs **before** execution; there is no execute-then-ask path.
- Agents hold no direct credentials, network path, or file handle to any tool.
- Each request records agent, tool, arguments (redacted per FR-13), timestamp, task, trace, previous action, risk assessment, decision with reason codes, and execution result.
- Internal typed interfaces inside the single Gateway process: `IdentityService`, `CapabilityService`, `PolicyService`, `ValidationService`, `TaskConsistencyService`, `BehaviorService`, `RiskService`, `DecisionService`, `ApprovalService`, `BreakerService`, `AuditService`, `IncidentService`.

**Normative evaluation order (invariant).** Stages may run in parallel for performance, but the security outcome must be equivalent to this sequence:

1. Authenticate request
2. Verify agent identity
3. Verify agent status
4. Verify task association
5. Verify capability
6. Resolve exact tool
7. Validate input schema
8. Normalize and validate parameters
9. Validate resource and destination scope
10. Evaluate task and intent consistency
11. Evaluate communication policy (when the action is a message or delegation)
12. Evaluate policy rules
13. Evaluate behavior and trace sequence
14. Calculate risk assessment
15. Run decision engine
16. Create approval state if required
17. Execute only after approval (or immediately on ALLOW/WARN)
18. Persist execution result
19. Update breaker, trust, security state and incidents
20. Publish event to the dashboard

Rules:

- Failures in stages 1–6 (identity, status, task, capability, tool resolution) short-circuit to BLOCK, with their reason codes recorded.
- For later stages, all results are collected so the decision carries complete reasons.
- **Honey tripwire.** For every request from an agent whose identity was verified, a cheap deterministic scan of the raw arguments for registered honey assets runs *even when the request short-circuits at stages 1–6*. Without this, a request denied at the capability stage would never reach parameter validation and the honey asset would go undetected.
- The decision is never a single score. The Decision Engine combines `PolicyResult`, `CapabilityResult`, `ParameterResult`, `TaskConsistencyResult`, `BehaviorResult`, `RiskAssessment` and `SecurityState`.
- A hard policy, capability or parameter denial cannot be softened by a low risk score.

### FR-1a Execution boundary and action lifecycle (P0)

> **Invariant:** No tool implementation is callable from agent code, orchestrator code, dashboard code, or an untrusted plugin except through the Gateway's execution interface.

```text
Agent request → Gateway authorization → Decision → Tool Executor interface → Registered tool implementation
```

No shortcut such as `from tools import read_secrets` is allowed anywhere, including the orchestrator. **Architectural tests** (import-graph and AST checks, e.g. with `import-linter`) fail the build on: direct imports of tool implementations by agents; direct HTTP clients in agent modules; filesystem access outside approved abstractions; Docker SDK use outside the executor service; database connections from agent code.

**Action lifecycle** (one state machine covering approval and execution):

```text
REQUESTED → AUTHORIZED ──────────────────────────────→ EXECUTING → SUCCEEDED | FAILED | CANCELLED | UNKNOWN_RESULT
          → BLOCKED
          → APPROVAL_PENDING → APPROVED → EXECUTING
                             → REJECTED | EXPIRED | STALE
```

**Idempotency.** Each action has an `execution_id` and an `idempotency_key`. A tool must never execute twice because the Gateway retried after a timeout.

- `UNKNOWN_RESULT` means the Gateway sent the request, the tool may have executed, and the response was lost. The default resolution is `REQUIRE_MANUAL_RECONCILIATION`.
- `execute_code`, external requests and database mutations are never retried automatically unless the tool registry declares idempotency support, in which case a retry reuses the same key.

### FR-2 Agent Registry (P0)

`agent_id`, name/role, owner, `allowed_tools`, `forbidden_tools`, `data_access_scope`, `max_risk_level`, `communication_permissions`, `task_association`, violation history, and two **independent** state fields:

- `status` (lifecycle): `active` | `suspended` | `retired`
- `security_state`: `CLEAN` | `EXPOSED` | `SUSPICIOUS` | `COMPROMISED` | `QUARANTINED` | `RECOVERED`

Plus `trust_score` (0–100, see FR-16). Roles are data; new roles need no kernel redeploy.

### FR-3 Tool Registry (P0)

`tool_id`, name, description, `input_schema`, `risk_level`, `required_permission`, `reversibility`, `allowed_agents`, `sensitive_parameters`, `allowed_destinations`, `rate_limits`, `sandbox_requirements`, `approval_requirements`, `idempotency` (declared: `none` | `key-supported`), enabled flag.

Initial tools: `search_documents`, `read_public_file`, `write_workspace_file`, `run_tests`, `execute_code`, `database_query`, `send_external_request`, `read_secrets`.

**Unregistered tools are rejected by default.** Lookup is exact-match only. Unregistered tools and integrations cannot execute through the AgentGuard-controlled tool plane (reason code `TOOL_UNREGISTERED`), and direct access is prevented by architecture because agents hold no external credentials, file handles or network path.

| Request | Outcome |
| --- | --- |
| Unknown or near-named tool | Rejected |
| Known tool, unsafe request | Evaluated, typically BLOCK or REQUIRE_APPROVAL |
| Known tool, safe request | Allowed according to policy |

"Not registered" never means "not monitored".

### FR-4 Identity and capability (P0)

The agent must exist, match its role, be `active`, be tied to the claimed task, and hold the tool. Resource-level scope and communication permissions are enforced identically. Sensitive tools are deny-by-default.

Agents authenticate with **short-lived Ed25519-signed tokens** issued by the Identity Manager, separate from human auth:

```json
{
  "iss": "agentguard-identity-manager",
  "sub": "researcher-01",
  "aud": "agentguard-gateway",
  "task_id": "task-501",
  "capability_version": "cap-v3",
  "scope": ["tool:search_documents"],
  "security_epoch": 4,
  "iat": 1790871000,
  "exp": 1790871060,
  "jti": "token-unique-id"
}
```

The Gateway verifies: signature, issuer, audience, expiry, agent `status`, task binding, `capability_version` and `security_epoch` against the registry, and (optionally) `jti` against a targeted revocation list.

- **`security_epoch`** is a per-agent counter. Quarantine or suspension increments it, which instantly invalidates every earlier token without an unbounded revocation list.
- **`scope`** may narrow but never widen what the registry grants. The registry stays authoritative.
- **`jti`** supports audit, forensics, replay detection and optional targeted revocation. It is not single use.
- Each request carries a unique `request_id`; a repeated `request_id` is rejected (`REQUEST_REPLAYED`).
- The orchestrator refreshes tokens only for active, non-quarantined agents.

### FR-5 Policy engine (P0)

Declarative, prioritized, versioned, auditable, individually toggleable rules over role, tool, task and resource. Rollback is supported.

**Enforcement class.** Every rule has `enforcement = hard | advisory`.

- `hard` rules force their outcome (`BLOCK`, `REQUIRE_APPROVAL` or `WARN`) regardless of risk score.
- `advisory` rules may only produce `WARN` or add risk factors. They never cause a block on their own. A task-inconsistency warning therefore cannot turn an otherwise safe action into a block unless a hard rule says so.

**Resolution algorithm:**

```text
ApplicablePolicySet (rules whose conditions match)
  → hard-deny evaluation
  → hard-approval evaluation
  → advisory/warning evaluation
  → default deny when nothing explicitly allows
```

**Precedence among applicable rules (highest first):** critical deny; identity and capability; resource and parameter; communication; task consistency; approval; warning; default deny.

**Conflicts:** among applicable hard outcomes, the most restrictive wins (`BLOCK` > `REQUIRE_APPROVAL` > `WARN` > `ALLOW`). Example: a resource rule "unallowlisted destination → BLOCK" and a role rule "external_request → REQUIRE_APPROVAL" resolve to BLOCK. A conflict-resolution test suite exists before the rule set grows.

**Expression language:** conditions are written in CEL with a strictly bounded input context. Policies cannot execute arbitrary Python or make network calls, and evaluation has time limits.

`SUSPEND` is a containment action triggered by the circuit breaker, not a decision outcome.

### FR-6 Parameter validation (P0)

Path traversal and symlink escape (resolve against allowed roots), secret/config paths, dangerous shell commands, non-allowlisted destinations (resolve and pin IPs to defeat DNS rebinding; block private ranges), URL schemes, payload size, schema conformance, unsafe queries, scope violations, dangerous execution flags, suspicious encodings.

### FR-7 Task / intent consistency (P0)

Each task has deterministic labels and an allowed-action set. Result is one of:

| Result | Example (task: "summarize a document") |
| --- | --- |
| `CONSISTENT` | `search_documents` |
| `SUSPICIOUS` | `write_workspace_file` |
| `INCONSISTENT` | `read_secrets` |

The result adds to risk, can trigger a warning, and can strengthen a block. It never overrides a hard capability or parameter rule, and it does not claim to understand intent perfectly. An LLM may supply an optional explanation signal only.

### FR-8 Risk engine (P0)

| Factor | Range |
| --- | --- |
| Tool sensitivity | 0–25 |
| Data sensitivity | 0–20 |
| Permission deviation | 0–20 |
| Destination risk | 0–15 |
| Behavioral anomaly | 0–10 |
| Irreversibility | 0–10 |

Defaults (configurable): 0–29 ALLOW · 30–49 WARN · 50–74 REQUIRE_APPROVAL · 75–100 BLOCK.

**Hard-signal floor.** If a critical event occurs (honeytoken touched, critical secret access, sandbox-escape signal, credential exposure, gateway-bypass attempt), then `risk_score = max(risk_score, 90)`. The cause is always retained and shown, e.g. `Risk: 96 | Hard signal: HONEY_ASSET_TOUCHED | Decision: BLOCK | Security state: COMPROMISED`.

**Cumulative risk.** Tracked per trace and per agent. No decay during an active trace or incident window, which keeps scoring easy to explain and replay. It resets on a new task, an explicit recovery, or a configured timeout. Cumulative risk can escalate a decision when no single step crosses a threshold.

### FR-9 Decision engine and reason codes (P0)

Exactly one outcome per action. Ambiguity or internal failure on critical tools resolves to BLOCK. Every decision carries machine-readable reasons with stable codes; human-readable text is generated from them.

```json
{
  "decision": "BLOCK",
  "reasons": [
    {
      "code": "CAPABILITY_DENIED",
      "message": "Researcher is not allowed to use read_secrets.",
      "severity": "critical",
      "source": "capability_engine"
    },
    {
      "code": "SENSITIVE_RESOURCE",
      "message": "Requested resource matches a protected secret path.",
      "severity": "critical",
      "source": "parameter_validator"
    }
  ]
}
```

Initial code set: `CAPABILITY_DENIED`, `TOOL_UNREGISTERED`, `SCHEMA_INVALID`, `PATH_TRAVERSAL`, `SENSITIVE_RESOURCE`, `DESTINATION_NOT_ALLOWLISTED`, `TASK_INCONSISTENT`, `COMM_PATH_DENIED`, `HONEY_ASSET_TOUCHED`, `CUMULATIVE_RISK_HIGH`, `BREAKER_TRIPPED`, `REQUEST_REPLAYED`, `TOKEN_INVALID`, `APPROVAL_STALE`, `EXECUTION_DUPLICATE`, `RESULT_UNKNOWN`. Codes drive tests, analytics, frontend filters, incident grouping, policy debugging and replay consistency. LLM-written summaries are optional and never the system of record.

### FR-10 Behavior and sequence analysis (P0 basic / P2 advanced)

Repeated failures and blocks, suspicious retries, unusual tool use, new communication partners, sensitive-resource access, privilege changes, and known multi-step patterns (e.g. read doc → extract instruction → access config → encode → external request) via per-trace state-machine matchers.

### FR-11 Prompt-injection defense (P0)

All retrieved content is untrusted. Enforce on the **resulting action attempts** through the same checks. Any classifier is a supplementary signal only.

### FR-12 Agent-to-agent security (P0)

Messages and delegations are evaluated against an approved graph (Planner→Researcher, Planner→Coder, Coder→Executor, Reviewer→Planner). Detect unknown agents, out-of-graph paths, circular delegation, impersonation.

### FR-13 Human approval (P0)

Execution genuinely pauses on a Postgres-backed state machine until a human approves or rejects. **Timeout resolves to reject.**

**What the approver sees.** An exact *structural* representation of the requested parameters, with classified values replaced by redaction tokens or secure references. The frontend never receives protected plaintext, except through the controlled reveal below.

```json
{
  "destination": "api.example.com",
  "api_key": {
    "classification": "secret",
    "display": "***************7F91",
    "secure_reference": "secret-ref-8821"
  },
  "payload": {
    "classification": "sensitive",
    "display": "[REDACTED: sensitive_data]"
  }
}
```

- **Controlled reveal:** an authorized approver may reveal a specific value. Each reveal is separately logged (who, what, when, why), shown transiently, and never written to logs or browser storage.
- Sensitive values never appear in dashboard responses, error messages, LLM prompts, logs, incident summaries or browser storage.
- The tool receives the original value through a server-side secure reference, never through the frontend.
- The view also shows agent, tool, task, reason codes, risk breakdown, fired policies, recent trace and affected resources. Decision, approver and time are logged immutably.

**Approval freshness.** Approval is valid only if the action is unchanged since the request was created. At request time the Gateway stores:

```text
fingerprint = SHA256( JCS({ agent_id, tool_id, normalized_arguments, task_id, trace_id, policy_version, resource_scope }) )
```

On approval the Gateway recomputes the fingerprint and rejects with `APPROVAL_STALE` if it differs. It also rejects when the agent became suspended or quarantined, the policy version changed, the destination changed, the tool definition changed, the task was cancelled, or the approval expired. (The fingerprint uses canonical JSON, not string concatenation, so field boundaries are unambiguous.)

**Reference approval scenario:** Executor calls `execute_code` with `network_access=false`, an isolated task workspace, Docker runtime and a 5-second timeout. Expected: `REQUIRE_APPROVAL`, risk about 61/100, with reasons such as high-impact code execution, exceeding default autonomy, and sandbox confirmation required. After approval: the sandbox starts, code runs, the result is captured, the container is destroyed, and an audit event is appended. The demo uses no real database deletion, external network calls or credentials.

### FR-14 Circuit breaker (P0)

Defaults: 3 medium violations in 60 s → warning escalation; 2 high-risk → temporary suspension; 1 critical → immediate block and suspension. On trip: suspend agent, isolate task if needed, create incident, notify admin, preserve trace. State survives restarts.

### FR-15 Sandbox (P0)

The Executor runs in a separate Docker container launched through the Docker SDK.

**Default profile** (configurable; Docker SDK equivalents of the Compose keys):

```yaml
read_only: true
network_disabled: true
user: "10001:10001"
cap_drop: [ALL]
security_opt:
  - no-new-privileges:true
  - seccomp:./seccomp/agent-executor.json
pids_limit: 64
mem_limit: 256m
cpus: 0.5
tmpfs:
  - /tmp:size=64m,noexec,nosuid,nodev
```

Plus a hard timeout and a per-task isolated workspace. **Never mount `/var/run/docker.sock`** (or any Docker socket) into the executor. `noexec` on tmpfs means only interpreted code runs; compiled binaries would need a separate decision.

**Limitation.** The P0 sandbox is a constrained demonstration environment, not a guarantee against all container escapes. Its real strength depends on host configuration, kernel security, runtime settings, image provenance and trust in the Docker daemon. Rootless Docker is recommended where available. Stronger isolation (gVisor, Firecracker) is P2. Sandbox escape attempts are critical events.

### FR-16 Deception, containment and security state (P0 minimal / P1 full)

- At least one HoneyTool and one Honeytoken with unique IDs (e.g. `AG-HONEY-7F92-XK11`) in P0. HoneyAgent is P1.
- **"Touched" means referenced, not read.** A honey asset is touched when a request's arguments, a message, or a tool name reference a registered honey asset ID, path or name, whatever the eventual decision. The request is blocked before execution, so the asset is never read and tool execution count stays 0. Required outcome: `Decision = BLOCK`, `security_state = COMPROMISED` then `QUARANTINED`, and `status` remains `active` until the circuit breaker trips.
- `security_state` and `trust_score` are **separate**. State controls containment; the score supports prioritization and explanation only.
  - Hard signals change state immediately: honeytoken touched → `COMPROMISED` (then auto-`QUARANTINED`); repeated medium violations → `SUSPICIOUS`; targeted by a compromised peer → `EXPOSED`.
  - A high score with a `COMPROMISED` state is valid, and so is a low score with `CLEAN`.
  - The circuit breaker changes `status` (to `suspended`), not `security_state`.
- Trust score starts at 100 with fixed deltas (warning −5, repeated warning −10, unauthorized tool −20, secret attempt −35, HoneyTool −40, safe task +2). It is **never** an access gate.
- **Quarantine permissions:** only an allow-list of AgentGuard-provided diagnostic operations (read own status and trace). No registered tools, no agent communication, no external network. Tokens are revoked.
- **Recovery:** human approval, a clean checkpoint, and a freshly issued short-lived token. State becomes `RECOVERED`.

### FR-17 Incidents (P0)

Incident/trace IDs, agent, task, severity, category, action, risk score, violated policies, description, timeline, resolution, agent status, recommended response. Lifecycle: DETECTED → ANALYZED → BLOCKED/CONTAINED → REVIEWED → RESOLVED.

### FR-18 Audit log (P0)

Append-only table with a per-chain sequence number. Hash definition (exact bytes):

```text
current_hash = SHA256( bytes.fromhex(previous_hash) + b"." + JCS(event_without_hash_fields) )
```

- `JCS` is RFC 8785 canonical JSON, UTF-8 encoded. The genesis `previous_hash` is 32 zero bytes.
- Each row stores `event_hash_algorithm = "SHA-256"`, `canonicalization = "RFC-8785"`, `chain_id`, `sequence`, `previous_hash`, `current_hash`.

**Single-writer guarantee, in layers** (PostgreSQL advisory locks are application-defined, so the database alone does not force every writer to use them):

1. A dedicated audit-writer function or service is the only write path.
2. An application-level advisory lock around appends.
3. The application role has `INSERT` and `SELECT` only; migrations use separate admin credentials.
4. A unique constraint on `(chain_id, sequence)`.
5. Triggers reject `UPDATE` and `DELETE`.
6. Tests open two concurrent writers and prove no duplicate sequence numbers or divergent links.
7. Chain verification runs after restart.

**What each mechanism detects:**

| Mechanism | Detects |
| --- | --- |
| Hash chain | Modification within the retained chain |
| Signed checkpoint (P1) | Truncation before the checkpoint |
| Checkpoint stored outside the database (P1) | Replacement of the entire local chain |

A database superuser can still alter data; the chain and checkpoints make that detectable. Checkpoints can be a signed file or export, with no blockchain needed.

### FR-19 Trace replay and attack-chain graph (P0)

Step-by-step chronological replay with a scrubber (state, permissions, trust, active policies, request, decision at each step). Graph nodes: agent, tool, file, API, message, policy, incident, approval. Edges: read, wrote, called, sent, delegated, blocked, approved, influenced.

### FR-20 Attack Laboratory

P0 scenarios: unauthorized tool use, prompt injection, secret-file access, unauthorized external request, repeated blocked action, unknown-agent communication. P1 adds: path traversal, privilege escalation, unsafe code, sandbox escape, tool-name manipulation, parameter tampering, malicious URL, gateway bypass, multi-step chain. Every run produces an incident and a replayable trace. The full lab runs in CI as a regression suite.

### FR-21 Dashboard

P0 views: Command Center, Live Activity, Agent Graph, Incident Center, Trace Explorer/Replay, Approval Center. P1: Risk Center, Policy Manager, Agent Manager, Tool Manager, Audit Integrity.

### FR-22 Simulation features (P1)

Agent Twin (declared vs. observed), Counterfactual mode (with/without AgentGuard, mock environment only, no real exfiltration), Policy Mutation (replay past attack against a weakened policy), Attack Director (attack × defense level), Protection Score with autonomy-preserved %.

### FR-23 Agent execution modes, LLM client and replay (P0)

- **Replay mode (mandatory, canonical test path):** recorded LLM outputs are replayed deterministically for the attack lab, CI and demos.
- **Live mode:** Groq through the LLM Client (default). **Offline mode (optional):** Ollama.
- All modes use the identical `authorize()` path, and none influences a security decision. Only the *requested action* varies between modes. The Gateway decision must be identical for identical agent, tool, arguments, task, trace state, policy version and resource state.
- **Determinism:** replay mode injects a deterministic clock and ID generator so audit hashes can match exactly. Where that is not possible, declared nondeterministic fields are excluded and a **normalized trace hash** is compared.
- **Proposals are untrusted.** The LLM Client returns an `AgentProposal(proposed_tool, arguments, source, confidence)`, never a trusted tool call. The Gateway treats Groq, Ollama, replay and hand-written malicious proposals identically.
- **Live-mode failure behavior:** LLM timeout → no action proposed. Malformed output → `SCHEMA_INVALID`. Rate limit → retry within budget, then the run terminates safely. Provider error → the task pauses and no tool executes. A failed LLM call is never converted into a fallback tool action.
- **Replay fixture format:**

```json
{
  "scenario_id": "prompt_injection_001",
  "fixture_version": "1.0",
  "llm_provider": "replay",
  "model": "recorded",
  "messages": [],
  "expected_decisions": [],
  "expected_incidents": [],
  "expected_trace_hash": ""
}
```

## 8. Non-Functional Requirements

| Area | Requirement |
| --- | --- |
| Latency | Policy decision \< 100 ms, no LLM in the path |
| Dashboard | Event-to-screen 1–2 s |
| Concurrency | ≥ 5 simulated agents, ≥ 100 events per run without degradation (floors, not ceilings) |
| Reliability | Fail closed for critical tools; logs, incidents, breaker state persist across restarts; tool failures don't corrupt traces; policy rollback |
| Determinism | Every BLOCK/QUARANTINE/breaker trip traces to a deterministic rule, honeytoken, or schema/capability check |
| Explainability | Every decision carries human-readable reasons |
| Cost | $0 to build, run locally, and demo; no paid dependency on any critical path |
| Portability | Whole system starts with one `docker compose up`; replay mode needs no network or key, live mode needs only a free Groq key |

## 9. Technology Stack (all free)

"Free" here means open source and free to self-host, or a free tier of a hosted service. Licenses below are from general knowledge; confirm each before commercial or redistributed use.

### 9.1 Architecture

A **modular monolith**: one Gateway process hosts the policy, risk, behavior and incident modules behind typed interfaces. This keeps the decision path in-process and easy to prove, and the modules can be split into services later. The Executor sandbox is a separate container.

### 9.2 Backend and security kernel

| Layer | Choice | Cost / license |
| --- | --- | --- |
| Language | Python 3.12+, mypy/pyright strict | Free (PSF) |
| API | FastAPI, Pydantic v2, Uvicorn | Free (MIT / BSD) |
| ORM / migrations | SQLAlchemy 2.0 async, Alembic | Free (MIT) |
| Policy conditions | CEL via `cel-python` | Free (Apache 2.0) |
| Canonical JSON | `rfc8785` | Free (Apache 2.0) |
| Signing / tokens | `cryptography` (Ed25519), PyJWT | Free (Apache/BSD, MIT) |
| Sequence analysis | `networkx` | Free (BSD) |
| Logging | structlog | Free (Apache/MIT) |

### 9.3 Data and messaging

| Layer | Choice | Cost / license |
| --- | --- | --- |
| Database | PostgreSQL 16+ (source of truth, partitioned `events`) | Free (PostgreSQL License) |
| Event delivery and counters | **Valkey** (Redis-compatible; Streams, short-lived counters) | Free (BSD-3) |
| Reliability pattern | Transactional outbox | n/a |
| Live updates | Server-Sent Events | n/a |

**Ownership:** Agents, tools, policies, tasks, approvals, incidents, audit events and breaker state live in PostgreSQL. Valkey carries live event delivery and short-lived counters only, and never becomes authoritative for a security decision. If Valkey is unavailable, breaker counters are recomputed from PostgreSQL and the Gateway fails closed for critical tools.

**Outbox flow:** write decision and event to Postgres → commit → publish to Valkey → dashboard receives the SSE update. If Valkey fails, events remain recoverable from Postgres.

### 9.4 Identity and auth

| Layer | Choice | Cost / license |
| --- | --- | --- |
| Agent identity | Custom signed tokens (above) | Free |
| Human auth (initial) | Auth.js with local credentials; roles admin / approver / viewer | Free (ISC/MIT) |
| Human auth (P2, SSO) | Keycloak self-hosted (OIDC) | Free (Apache 2.0); heavy on memory |

### 9.5 Execution

| Layer | Choice | Cost / license |
| --- | --- | --- |
| Sandbox | Docker Engine + Docker SDK for Python | Engine free (Apache 2.0). Docker Desktop is free for personal, education and small businesses; larger orgs need a paid plan, so Podman or Colima are free alternatives |
| Hardening (P2) | gVisor (runsc); Firecracker (needs KVM) | Free (Apache 2.0) |

### 9.6 Agents and LLM

| Layer | Choice | Cost / license |
| --- | --- | --- |
| Orchestrator | Custom async Python state machine | Free |
| LLM abstraction | LiteLLM (library only; skip its paid proxy features) | Free (MIT) |
| **Default LLM (live mode)** | **Groq API (free plan) via LiteLLM**, model ID pinned in configuration | Free plan, rate-limited, no credit card required. Terms can change |
| Offline mode (optional) | Ollama with a local open-weight model (e.g. Qwen3 8B Q4_K_M, about 5.2 GB, fits 8 GB VRAM) | Ollama is free (MIT). Model licenses vary, so check each |
| Other hosted LLMs (dev/test only) | Gemini API free tier (Flash / Flash-Lite); OpenRouter free models | Free tier, rate-limited. See caveats below |
| **Replay mode (mandatory)** | Recorded LLM responses replayed deterministically; no LLM calls, no network | Free |

**Decision: LLM architecture (resolved)**

| Mode | Provider | Purpose | Required |
| --- | --- | --- | --- |
| Live | Groq | Normal multi-agent execution | Default |
| Offline | Ollama | No-internet or local testing | Optional |
| Replay | Recorded responses | Demo, CI, attack lab | **Mandatory** |

- **No model takes part in any security decision.** The LLM decides only what an agent *wants* to do. AgentGuard decides whether it is *permitted*. The critical path stays: Agent → Gateway → deterministic checks → ALLOW / WARN / REQUIRE_APPROVAL / BLOCK.
- **Agents never call an LLM directly.** The orchestrator requests completions through the **LLM Client**, a trusted platform component outside agent reach. Agent tool and message requests go through the Gateway.
- **LLM Client responsibilities:** rate limiter, retry with exponential backoff on HTTP 429, per-run request budget, response cache, model registry, API-key isolation, and a single async queue with timeouts.
- **Configuration, not code, selects the model:**

```env
LLM_PROVIDER=groq          # groq | ollama | replay
LLM_MODE=live              # live | offline | replay
GROQ_MODEL=<pinned-model-id>
```

- **Every trace records** `llm_provider`, `model`, `mode` and `trace_id`, so runs are reproducible even as provider catalogs change.
- **Do not hard-code a Groq model.** Choose one from Groq's current models page after benchmarking structured tool-call reliability on AgentGuard's agent prompts. Catalogs and limits change, so re-check before pinning.
- **API-key isolation.** `GROQ_API_KEY` lives only in the LLM Client's environment. No agent, tool, sandbox or workspace file can read it, and agents cannot reach Groq directly. Agents never hold the credential that enables their own LLM access.
- **Data egress.** Prompts and responses sent to Groq leave the machine. Use only synthetic documents and fake honeytokens, never real secrets or data.
- **Rate limits.** Groq usage is subject to provider-defined organization, project and model rate limits. AgentGuard must not rely on multiple API keys or accounts to increase capacity.
- **Prompt caching.** Keep system prompts stable, since cached prompt tokens do not count toward Groq rate limits.
- **Redaction before egress.** The LLM Client applies the same data-classification rules as FR-13, so sensitive values are never placed in prompts.
- **Model selection is ADR-004.** Benchmark candidate Groq models with: 30 normal tool-call prompts, 20 malformed-output prompts, 20 prompt-injection prompts, 10 multi-agent delegation prompts, 10 long-context prompts. Score: valid structured output 30%, correct tool proposal 25%, latency 15%, prompt-injection reproducibility 10%, rate-limit tolerance 10%, context handling 10%. The result is only for live-mode convenience; replay remains canonical. Live Groq behavior is never a prerequisite for CI, the attack lab, the core demo, or any security decision. Limits are per model and change, so check the console immediately before benchmarking and spread large benchmarks across models or days.
- **Per-run budget is configuration, not code:**

```env
RUN_MAX_LLM_REQUESTS=32
RUN_MAX_INPUT_TOKENS=40000
RUN_MAX_OUTPUT_TOKENS=8000
RUN_MAX_DURATION_SECONDS=180
```

Starting targets: normal demo 20 requests, attack demo 24, benchmark 100. Keep the demo comfortably below current provider limits.

- **Constrain outputs** with structured-output schemas. Malformed tool calls are rejected by the Gateway as schema failures, which is correct behavior but can hurt demo flow, so record good runs for replay.
- **Record once, replay forever.** Capture real Groq responses for the attack lab and demo, then replay them for deterministic CI and rehearsals.
- **Ollama notes (offline mode only):** 14B-class models (about 9.3 GB) exceed 8 GB VRAM. Qwen3 "thinking" mode adds latency, so disable it by default. One GPU serves one request at a time, so concurrent agents queue.

**LLM free-tier caveats (checked October 2026):**

- Groq's free plan requires no credit card and is governed by rate limits rather than a monthly token budget. Limits are set per model and published figures vary by source, so read the limits page in your Groq console rather than trusting any quoted number. Reviews note there is no privacy guarantee on the free tier.
- Google restructured Gemini API pricing on April 1, 2026: the free tier is Flash and Flash-Lite only, Pro models are paid-only, and free rate limits were cut. Published figures vary by source and change often, so check Google's rate-limits page rather than hard-coding numbers.
- The free tier excludes commercial use, and Google may use free-tier inputs and outputs to improve its models. Send no real or customer data through it.
- Because free tiers shift without notice, **no core feature may depend on a hosted LLM.** Scripted mode and Ollama are the guaranteed paths.

### 9.7 Frontend

| Concern | Choice | Cost / license |
| --- | --- | --- |
| Framework | Next.js (App Router), TypeScript strict | Free (MIT). Run locally; no paid hosting needed |
| Styling / components | Tailwind CSS, shadcn/ui | Free (MIT) |
| Server state / types | TanStack Query, `openapi-typescript` + `openapi-fetch` | Free (MIT) |
| Graphs | React Flow (`@xyflow/react`), dagre or elkjs | Free (MIT; EPL-2.0 for elkjs). Paid "Pro" examples are optional and not used |
| Charts | Recharts | Free (MIT) |
| Tables / forms | TanStack Table, react-hook-form, zod | Free (MIT) |
| Policy editor | Monaco editor | Free (MIT) |
| Motion | Framer Motion (Motion) | Free (MIT) |

### 9.8 Observability, quality and tooling

| Concern | Choice | Cost / license |
| --- | --- | --- |
| Observability | OpenTelemetry, Prometheus, Grafana OSS (self-hosted) | Free (Apache 2.0; Grafana is AGPL, fine for internal use) |
| Repo tooling | uv, pnpm, Turborepo, ruff, pre-commit | Free (MIT/Apache) |
| Testing | pytest, hypothesis, Schemathesis, testcontainers, Vitest, Playwright | Free (MPL/MIT/Apache) |
| Security scanning | Semgrep CE, pip-audit, Trivy | Free |
| CI | GitHub Actions | Free for public repos; private repos get a limited free monthly quota (check current limits). `docker compose` plus `make test` locally is the zero-cost fallback |
| Hosting | None required. Everything runs locally via Docker Compose | $0 |

### 9.9 Deliberately excluded

Neo4j (Postgres edge tables + networkx suffice) · Kafka (Valkey Streams suffice) · Temporal (Postgres state machine suffices) · ML anomaly detection (P2) · GraphQL · SQLite · blockchain · any paid SaaS on the critical path.

## 10. Data Model and APIs

**Tables:** agents, tools, policies (versioned), tasks, events (hash-chained), incidents, approvals, traces, violations, agent_communications, risk_assessments, honey_assets, checkpoints, executions (with `execution_id`, `idempotency_key`, lifecycle state). `agents` carries `status`, `security_state`, `trust_score` and `security_epoch`; `approvals` carries the action fingerprint and policy version.

**APIs:** `POST/GET /agents`, `PATCH /agents/{id}/status`, `POST /agents/{id}/suspend|resume`, `POST/GET /tools`, `POST /tasks`, `GET /tasks/{id}`, `POST /actions/evaluate`, `POST /actions/execute`, `GET /traces/{id}`, `GET /incidents[/{id}]`, `POST /approvals/{id}/approve|reject`, `GET /events`, `GET /risk`, `GET /policies`, `GET /audit/verify`, and an SSE stream at `/events/stream`. Types for the frontend are generated from the OpenAPI schema.

## 11. Repository Structure

```
agentguard/
  apps/dashboard/            # Next.js
  apps/gateway/              # FastAPI entrypoint, authorize()
  core/                      # modules inside the Gateway process
    identity/ capabilities/ policy/ validation/
    risk/ behavior/ sequence/ approval/
    breaker/ audit/ incidents/
  services/executor/         # separate sandbox service
  agents/                    # planner, researcher, coder, executor, reviewer
  sdk/                       # agentguard-py client
  deception/                 # honey tools, tokens, agents
  simulations/               # attacks, scenarios, recorded LLM traces
  shared/                    # schemas, events, types (contracts)
  infrastructure/            # compose, migrations, grafana
  tests/  docs/  (docs/adr/ holds the ADRs)
```

## 12. Success Metrics

| Metric | Definition |
| --- | --- |
| Detection rate | detected simulated attacks ÷ total, over the defined fixture set |
| False-positive rate | legitimate actions wrongly blocked ÷ total legitimate, over a fixed legitimate-action set |
| **Post-block execution rate** | blocked unsafe actions that reached execution ÷ total blocked unsafe actions × 100. **Target: 0%** |
| Policy coverage | tested unsafe categories ÷ planned |
| Prevented attack chains | multi-step chains stopped before completion |
| Incidents correctly reconstructed | replays matching what happened |
| Performance | policy latency, tool latency, dashboard latency, events/sec, memory |
| Protection Score (P1) | composite 0–100 plus autonomy-preserved % |

Targets: 100% of the defined attack fixtures detected and ≤ 5% false positives on the fixed legitimate set. A fixed fixture set is a regression gate, not evidence of coverage against unknown attacks, and the project makes no such claim.

## 13. Acceptance Criteria

### 13.1 P0 vertical slice (end-to-end flow)

1. Planner creates a task
2. Planner delegates to Researcher through the Gateway
3. Researcher performs a legitimate search (ALLOW)
4. Researcher returns its result through the Gateway
5. Coder writes a file through the Gateway (ALLOW)
6. Executor requests `execute_code`
7. Gateway returns `REQUIRE_APPROVAL`
8. A human approves
9. The sandbox executes safely and the result is logged
10. A malicious document is introduced
11. Researcher requests `read_secrets` with the honeytoken path as its target
12. Gateway BLOCKs it before execution with reason codes `CAPABILITY_DENIED`, `SENSITIVE_RESOURCE` and `HONEY_ASSET_TOUCHED`; tool execution count is 0
13. The honey tripwire raises the Critical deception alert (the asset is referenced, never read)
14. Researcher becomes `COMPROMISED` and is auto-quarantined
15. Researcher messages Coder
16. Communication policy BLOCKs it
17. Researcher retries
18. Circuit breaker trips; `status` becomes `suspended`
19. Incident is stored
20. Trace is replayed
21. Attack-chain graph is displayed
22. Audit verification passes

This shows useful autonomy (ALLOW), a high-impact action waiting on a human (REQUIRE_APPROVAL), a malicious action stopped (BLOCK), and repeated compromise contained.

### 13.2 System criteria

1. Every decision includes stable reason codes and generated messages.
2. A test proves no tool executes without a prior `authorize()` decision.
3. **Invariant test:** agents hold no direct credentials, network path or file handles (container environment inspection, network-probe from the sandbox, static check that agent code imports no tool clients).
4. The Groq API key is unreadable by any agent, tool or sandbox.
5. Post-block execution rate is 0% across the full Attack Lab.
6. The same scenario run twice in replay mode yields identical decisions and identical normalized trace hashes (identical audit hashes when the deterministic clock and ID generator are in use).
7. A tampered copy of the audit log fails verification; the original passes. `UPDATE`/`DELETE` on the audit table are rejected for the application role.
8. Sensitive values are redacted in approvals, logs, prompts and API responses; a reveal is separately logged.
9. `docker compose up` starts the system in replay mode with no account, key or network; live mode needs only a free Groq key.
10. Every trace records `llm_provider`, `model` and `mode`.
11. An approval whose action fingerprint, policy version, agent state, task state or resource scope changed is rejected with `APPROVAL_STALE`.
12. A Gateway retry after a timeout never executes a tool twice; a lost response yields `UNKNOWN_RESULT` and manual reconciliation for non-idempotent tools.
13. Two simultaneous audit writers cannot create duplicate sequence numbers or divergent chain links.
14. Architectural tests fail the build if agent, orchestrator or dashboard code imports a tool implementation or opens its own network, file, Docker or database access.
15. The executor container has no Docker socket mounted, no network, and runs with the default security profile (FR-15).
16. A request denied at the capability stage that references a honey asset still raises `HONEY_ASSET_TOUCHED`, sets `security_state` to `COMPROMISED`, and shows execution count 0.

## 14. Roadmap (dependency order, no calendar)

| Phase | Deliverable | Depends on |
| --- | --- | --- |
| 0 | Shared contracts, repository, CI, Compose | none |
| 1 | Gateway identity, capability, policy on a stub tool | 0 |
| 2 | PostgreSQL, audit chain, outbox, Valkey | 1 |
| 3 | Parameter validation, task consistency, risk | 1 |
| 4A | Scripted agents against an in-memory event sink | 1, 3 |
| 4B | Persistent orchestrator and replay traces | 2, 4A |
| 5 | Breaker, approval, incidents, quarantine, honey assets | 2, 4B |
| 6 | Dashboard and SSE | 2, 5 |
| 7 | Attack laboratory and CI regression suite | 4B, 5 |
| 8 | Docker executor sandbox | 4B |
| 9 | P1 differentiators | 6, 7, 8 |
| 10 | P2 platform | 9 |

**Critical path:** 0 → 1 → 3 → 4A → 4B → 5. Phase 2 runs in parallel with 3 and 4A and must finish before 4B. Phase 4A keeps the system demoable early without pretending persistence is optional. Every phase ends with a runnable build.

## 15. Testing Strategy

- **Unit:** registries, permissions, parameter rules, policy precedence and conflicts, risk and cumulative risk, breaker thresholds, hash chain, reason codes, token verification
- **Negative authorization tests:** wrong role, suspended or quarantined agent, expired or revoked token, wrong audience, task mismatch, stale `capability_version`, repeated `request_id`, unknown tool, near-named tool, widened scope, forbidden destination, out-of-graph message
- **Property-based (hypothesis):** path and URL validators, canonicalization, hash-chain formatting
- **Integration:** agent→gateway→tool, blocked path, approve/reject/timeout, redaction and reveal logging, incident creation, suspension, trace correctness, SSE delivery, Valkey outage behavior, database role restrictions
- **Invariant and architectural tests:** no direct credentials/network/file handles; no execution after BLOCK; import-graph checks for the FR-1a invariant
- **Concurrency and idempotency tests:** two concurrent audit writers; duplicate `request_id`; duplicate `idempotency_key`; lost-response (`UNKNOWN_RESULT`) handling
- **Approval freshness tests:** altered arguments, policy version change, agent quarantined during pending approval, task cancelled, approval expired
- **Security:** injection, tool-name obfuscation, parameter tampering, traversal, malicious URLs, unknown-agent contact, retry abuse, privilege escalation, gateway bypass, log tampering, sandbox escape
- **API fuzzing:** Schemathesis against the OpenAPI schema
- **E2E:** Playwright through the 22-step flow

Frontend implementation note: build the six P0 views from shared components (shell, stats, event stream, agent graph, risk badge, incident panel, trace timeline, approval modal, policy explanation), not six separate pages.

## 16. Risks and Limitations

| Risk | Mitigation |
| --- | --- |
| Free LLM tiers change, throttle or disappear | Replay mode mandatory; Ollama optional; model pinned in config and ADR; LLM Client handles 429s, budgets and caching |
| Model emits malformed or off-task tool calls | Structured outputs, retry limits, recorded traces; malformed calls are schema failures |
| Prompts leave the machine; free tier has no privacy guarantee | Synthetic data only; redaction before egress |
| API key leakage to an agent | Key confined to the LLM Client; no direct provider access for agents; test enforces it |
| Network outage during a demo | Replay mode, recorded traces |
| Unregistered tools or integrations | Rejected by default (`TOOL_UNREGISTERED`); agents hold no external credentials, handles or network path; invariant tests |
| Container escape despite the sandbox profile | P0 sandbox is a constrained demonstration environment, not escape-proof; non-root, no network, dropped capabilities, seccomp, no Docker socket; gVisor/Firecracker in P2 |
| Stale or replayed approval | Action fingerprint, policy version and state checks (`APPROVAL_STALE`) |
| Duplicate execution after a retry | `execution_id`, `idempotency_key`, `UNKNOWN_RESULT` handling |
| Audit tail truncation or full-chain replacement by a privileged admin | Signed checkpoints, stored outside the database (P1) |
| Sensitive data exposed in approval or logs | Policy-based redaction, secure references, logged reveals |
| Scope creep from cyber-range features | Enforce the priority list; P1 never displaces P0 |
| Building every P0 item at once | Follow the dependency-ordered roadmap; keep the spine runnable at each phase |
| Rule-based engines miss novel attacks | Position as defined-class detection; behavioral engine in P2 |
| Over-blocking | Track false positives and autonomy preserved |
| License drift in dependencies | Pin versions; license check in CI |

**Limitations.** AgentGuard governs agents running inside its controlled runtime. Agents or processes deployed outside that runtime, or with their own credentials, are out of scope. It does not claim to prove an agent is safe; it prevents and detects clearly defined classes of unsafe runtime behavior.

## 17. Decisions and Open Questions

### Resolved

| Question | Decision |
| --- | --- |
| Detection and false-positive targets | 100% of defined fixtures; ≤ 5% false positives on the fixed legitimate set (Section 12) |
| Reviewer agent | P1. Planner, Researcher, Coder and Executor are P0 |
| Live approval operation | Executor `execute_code` in an isolated sandbox (FR-13) |
| Quarantine permissions | Diagnostics provided by AgentGuard only; no tools, communication or network (FR-16) |
| Recovery flow | Human approval + clean checkpoint + fresh short-lived token |
| Default LLM | Groq via LLM Client; Ollama optional; replay mandatory |
| Groq model selection | ADR-004 benchmark with weighted scoring (Section 9.6); not chosen in the PRD |
| LLM request budget | Configuration with starting targets (Section 9.6); verify against console limits before benchmarking |
| Container runtime | Docker Compose standard, with Podman or Colima as the fallback |

### Still open

1. **Assign the Integration Owner** (a person, not necessarily the most senior developer). Responsibilities: own `shared/` contracts and approve schema changes; maintain the dependency graph and ADRs; merge integration branches; run the full replay suite before merges; prevent direct tool bypass; own Compose health checks. This role protects coherence and does not implement every module.
2. Result of ADR-004 (the pinned Groq model ID).

## 18. Architecture Decision Records and Next Deliverable

Create these ADRs before coding. Each contains: context, decision, alternatives considered, consequences, security implications, test implications.

```text
ADR-001 Modular monolith and Gateway boundary
ADR-002 Replay as canonical execution mode
ADR-003 Agent token and capability model
ADR-004 Groq model selection
ADR-005 Policy precedence and conflict resolution
ADR-006 Approval freshness and action fingerprinting
ADR-007 Executor sandbox security profile
ADR-008 Audit-chain canonicalization and checkpoints
ADR-009 Postgres/Valkey ownership
ADR-010 P0/P1 feature boundary
```

From here on, changes go through ADRs, versioned schemas, pull requests and test-backed amendments rather than further PRD rewrites.

**Next document: the Engineering Master Plan**, covering architecture lock (components, trust boundaries, data flow, deployment), shared contracts (`ActionRequest`, `Decision`, `Reason`, `Agent`, `Tool`, `Policy`, `Task`, `TraceEvent`, `Approval`, `Incident`), Gateway stage interfaces, database schema and roles, API contracts and SSE events, replay system, executor sandbox, attack laboratory expectations, dashboard components, and team execution (ownership, branching, merge gates, definition of done).