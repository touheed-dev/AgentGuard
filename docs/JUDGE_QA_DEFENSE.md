# AgentGuard: Judge Q&A Defense & Battle Sheet

This battle sheet prepares presenters for sharp, adversarial questions from technical judges, security architects, and venture evaluators.

---

## Core Invariant (The 1-Sentence Anchor)

> **"Agents propose actions. AgentGuard decides whether those actions are allowed to happen."**

---

## Question Matrix

---

### Q1: "What prevents a rogue or compromised agent from simply executing the tool directly and bypassing your Gateway?"

* **10-Second Answer:**  
  "Agents have zero execution credentials or socket access. Tools can only be invoked by the Gateway executor using internal, short-lived execution secrets."
* **30-Second Technical Answer:**  
  "The system operates with strict architectural separation. Tool implementations and container sockets are not importable or routable from agent runtimes. Every tool request requires a Gateway-signed cryptographic token with a tight TTL, specific task ID binding, and matching security epoch. If an agent attempts direct execution or sends a forged token, the request fails closed with `TOKEN_INVALID`."
* **Evidence / Demo Location:**  
  - [backend/core/gateway.py](file:///w:/AgentGuard/backend/core/gateway.py#L125-L135) (`verify_token` + subject/task check).
  - Terminal: `python scripts/verify_demo_flow.py` (Step 2 shows immediate rejection).
* **Likely Follow-up Question:**  
  *"What if an agent steals another agent's token?"*  
  **Counter:** "Tokens are bound to agent ID and task scope. An agent cannot use another agent's token without failing the subject verification check."
* **What NOT to Claim:**  
  ❌ *Do NOT claim that agents run inside the Gateway process.* They are external clients communicating via the Gateway boundary.

---

### Q2: "Why can't an LLM simply trick or bypass your security rules through advanced prompt injection?"

* **10-Second Answer:**  
  "AgentGuard does NOT use an LLM to judge an LLM. Our security evaluation is 100% deterministic code, regex, AST schemas, and CEL policy rules."
* **30-Second Technical Answer:**  
  "Relying on an LLM to detect prompt injection is fundamentally vulnerable to prompt injection. AgentGuard enforces deterministic, in-process security rules: strict JSON schema validation, regex path traversal filters (`../`), private IP/SSRF blocks, capability matrices, and canary token scanners. The decision logic is deterministic code, guaranteeing repeatable, fail-closed enforcement."
* **Evidence / Demo Location:**  
  - Attack Lab Tab: Select **Scenario 1 (Prompt Injection)** or **Scenario 3 (Path Traversal)**.
  - Notice the Gateway decision: `BLOCK` with explicit reason codes `PATH_TRAVERSAL` / `SENSITIVE_RESOURCE`.
* **Likely Follow-up Question:**  
  *"What if the injection payload is semantically obfuscated?"*  
  **Counter:** "We enforce parameter type schemas and downstream honey assets. If obfuscated input attempts unauthorized tool calls or accesses unauthorized resources, capability scoping and canary tripwires catch it."
* **What NOT to Claim:**  
  ❌ *Do NOT claim that AgentGuard has a magic AI classifier that detects 100% of all possible semantic prompt injections.* Claim deterministic execution-boundary enforcement.

---

### Q3: "How does the Deception & Honey Asset system work in practice?"

* **10-Second Answer:**  
  "We inject synthetic canary credentials into agent context. The moment an agent touches a canary, it triggers an instant tripwire that quarantines the agent and revokes its tokens."
* **30-Second Technical Answer:**  
  "The Gateway maintains a registry of synthetic honey assets (canary AWS keys, database connection strings, fake file paths). Legitimate tasks have zero reason to reference these tokens. When an infected or rogue agent attempts to exfiltrate or use a canary (e.g., `AG-HONEY-7F92-XK11`), the Gateway immediately transitions the agent to `QUARANTINED`, sets status to `SUSPENDED`, and increments its `security_epoch`, which cryptographically invalidates all previously issued tokens across the swarm."
* **Evidence / Demo Location:**  
  - Attack Lab Tab: Select **Scenario 5 (Honey Asset Interaction)**.
  - Show the live agent state flip from `CLEAR` to `QUARANTINED` and status to `suspended`.
* **Likely Follow-up Question:**  
  *"Can a quarantined agent un-quarantine itself?"*  
  **Counter:** "No. Quarantine state is stored authoritatively in the Gateway and PostgreSQL. Releasing quarantine requires administrative intervention."
* **What NOT to Claim:**  
  ❌ *Do NOT claim that honeytokens prevent all memory scanning.* They act as high-fidelity tripwires to detect and isolate compromised agents rapidly.

---

### Q4: "Is your Docker sandbox 100% escape-proof against kernel exploits?"

* **10-Second Answer:**  
  "No container sandbox is mathematically escape-proof against kernel zero-days, which is why AgentGuard enforces defense-in-depth: malicious actions are blocked at the Gateway before reaching the container."
* **30-Second Technical Answer:**  
  "We apply an industry-hardened container isolation profile: `read_only` root filesystem, `cap_drop: ALL`, `no-new-privileges: true`, non-root user `10001:10001`, `network_mode: none`, tmpfs workspace, and strict seccomp filtering. More importantly, the Gateway filters and rejects unauthorized or malicious requests upfront, so the sandbox only ever executes pre-authorized, sanitised workloads."
* **Evidence / Demo Location:**  
  - [backend/services/docker_executor.py](file:///w:/AgentGuard/backend/services/docker_executor.py#L30-L55) (Container sandbox configuration).
  - [docs/adr/ADR-007-executor-sandbox-security-profile.md](file:///w:/AgentGuard/docs/adr/ADR-007-executor-sandbox-security-profile.md).
* **Likely Follow-up Question:**  
  *"Why not use microVMs like Firecracker?"*  
  **Counter:** "Our modular executor architecture is designed to support microVM backends (like Firecracker/gVisor) as a drop-in execution provider without altering the Gateway security kernel."
* **What NOT to Claim:**  
  ❌ *NEVER claim 'our Docker container cannot be escaped.'* Always frame it as a hardened defense-in-depth boundary.

---

### Q5: "How does the Cryptographic Audit Ledger guarantee tamper resistance?"

* **10-Second Answer:**  
  "Every event is hashed using RFC-8785 JSON Canonicalization and linked into a SHA-256 Merkle chain that can be mathematically verified from Genesis."
* **30-Second Technical Answer:**  
  "Standard database logs can be surreptitiously modified by privileged users or attackers. AgentGuard canonicalizes every decision payload into RFC-8785 JCS, computes `SHA-256(bytes(prev_hash) + '.' + JCS(event))`, and records the chain in PostgreSQL with row-level integrity checkpoints. Our `/audit/verify` endpoint walks the hash chain from the Genesis block to prove mathematical integrity."
* **Evidence / Demo Location:**  
  - Dashboard Checkpoints Tab: Click **Verify Audit Integrity**.
  - Show live endpoint response: `verified: true, checked_events: N`.
* **Likely Follow-up Question:**  
  *"What happens if an attacker modifies a row in PostgreSQL?"*  
  **Counter:** "The next hash calculation in the chain will fail to match the downstream block's `prev_hash`, causing `/audit/verify` to immediately flag the tampering."
* **What NOT to Claim:**  
  ❌ *Do NOT claim this is a public cryptocurrency blockchain.* It is a high-performance RFC-8785 cryptographic Merkle audit ledger designed for enterprise compliance.

---

### Q6: "What is the runtime performance and latency overhead introduced by the Gateway?"

* **10-Second Answer:**  
  "Under our measured test conditions, in-memory deterministic evaluation completes in under 2 milliseconds, which is negligible compared to LLM inference latency."
* **30-Second Technical Answer:**  
  "Because all Gateway checks—cryptographic token validation, circuit breaker inspection, parameter validation, risk scoring, and canary checks—are evaluated in-process using compiled rules, local evaluation overhead is measured at 1–2ms. Compared to typical LLM generation times of 500ms–2000ms, this evaluation overhead represents less than 0.5% of total request turnaround."
* **Evidence / Demo Location:**  
  - [docs/FINAL_BUILD_REPORT.md](file:///w:/AgentGuard/docs/FINAL_BUILD_REPORT.md).
  - Telemetry Chart on dashboard Command Center.
* **Likely Follow-up Question:**  
  *"Does PostgreSQL persistence slow down execution?"*  
  **Counter:** "We use async outbox and Valkey for ephemeral coordination, ensuring the hot path is non-blocking."
* **What NOT to Claim:**  
  ❌ *Do NOT claim <2ms is a universal SLA guarantee across all network topologies.* Frame it accurately as the measured in-memory deterministic evaluation overhead under tested conditions.

---

### Q7: "How do Human-in-the-Loop approvals prevent Time-of-Check to Time-of-Use (TOCTOU) attacks?"

* **10-Second Answer:**  
  "Approvals generate a cryptographic action fingerprint. When an operator approves, the Gateway verifies the fingerprint matches the exact payload before releasing execution."
* **30-Second Technical Answer:**  
  "When an action requires human approval (e.g., risk score ≥ 70 or sensitive tool), the Gateway creates a pending approval record with a SHA-256 fingerprint of the tool name and exact arguments. When an operator approves, a freshness token is issued. When execution is attempted, the Gateway re-computes the parameter fingerprint; if the agent or adversary modified even a single byte in the parameters, the fingerprint fails and the execution is blocked."
* **Evidence / Demo Location:**  
  - [backend/core/approval/service.py](file:///w:/AgentGuard/backend/core/approval/service.py).
  - [docs/adr/ADR-006-approval-freshness-and-action-fingerprinting.md](file:///w:/AgentGuard/docs/adr/ADR-006-approval-freshness-and-action-fingerprinting.md).
* **Likely Follow-up Question:**  
  *"What if an approval token expires?"*  
  **Counter:** "Approval tokens have a strict 300-second freshness window. Stale tokens are rejected with `APPROVAL_STALE`."
* **What NOT to Claim:**  
  ❌ *Do NOT claim that human operators review every low-risk action.* Approvals are reserved for high-risk threshold operations.
