# AgentGuard: 3–5 Minute Live Hackathon Demo Script

> **The Core Narrative:**  
> *"Autonomous agents are being given access to tools, databases, and APIs—but granting them direct execution authority creates severe prompt injection and privilege escalation risks. AgentGuard is a deterministic runtime security gateway: no agent ever executes a tool directly. Every action is mediated, inspected, risk-scored, and cryptographically audited before execution. When an action is blocked, execution is guaranteed at 0.00%."*

---

## Demo Setup Checklist (T-Minus 1 Minute)

1. **Stack Running**: Gateway, PostgreSQL, and Valkey healthy (`docker compose ps`).
2. **Dashboard Open**: Browser navigated to `http://localhost:5173` (Command Center tab).
3. **Terminal Open**: Terminal ready in `w:\AgentGuard` to run `python scripts/verify_demo_flow.py` if judges prefer CLI verification.
4. **State Pristine**: Click **`RESET DEMO`** in the top navigation bar.

---

## Presentation Sequence & Timing

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 0:00 - 0:45 │ The Problem & The Gateway Kernel                         │
 │ 0:45 - 1:30 │ Act 1: Authorized Action (ALLOW)                         │
 │ 1:30 - 2:30 │ Act 2: Prompt Injection / Path Traversal (BLOCK 0.00%)   │
 │ 2:30 - 3:30 │ Act 3: Deception Tripwire (HONEYTOKEN → QUARANTINE)      │
 │ 3:30 - 4:15 │ Act 4: Cryptographic Audit Chain & Replay               │
 │ 4:15 - 5:00 │ Conclusion, Key Takeaways & Judge Q&A                    │
 └────────────────────────────────────────────────────────────────────────┘
```

---

### Act 0: The Hook & Clean Posture (0:00 – 0:45)

**Speaker Narration:**
> "Welcome! As LLM agents become autonomous, enterprise security teams face a critical dilemma: how do you allow agents to call tools without giving them unfettered power to run malicious commands, leak API keys, or access sensitive files?
> 
> Here on the screen is **AgentGuard**—an execution-boundary security gateway for autonomous AI agents.
> Notice our top status: **Fail-Closed Invariant Active**, **Post-Block Exec Rate at 0.00%**, and all agent tokens signed with cryptographic capability scopes.
> Let's reset the system to pristine state with one click."

**Screen Action:**
- Click the **`RESET DEMO`** button in the Navbar.
- Point to the toast notification: `DEMO RESET COMPLETE`.
- Point out the 4 registered agents (`planner-01`, `researcher-01`, `coder-01`, `executor-01`) in `HEALTHY` state.

---

### Act 1: Authorized Normal Agent Action (0:45 – 1:30)

**Speaker Narration:**
> "First, let's see a normal, authorized workflow. The `executor-01` agent proposes an authorized data analysis task with the `echo` tool.
> It requests a capability token bound to `task-1` and presents it to the Gateway."

**Screen Action / Demo Trigger:**
- Click into the **20-Stage Pipeline** tab.
- Click **Execute Legitimate Action** (or switch to Command Center to see the live feed).

**Speaker Narration:**
> "The Gateway evaluates:
> 1. Token identity and task consistency: **VALID**
> 2. Circuit breaker state: **NORMAL**
> 3. Tool parameters and schema: **CLEAN**
> 4. Decision: **ALLOW**. The action executes in an isolated environment, and the result is returned."

---

### Act 2: Prompt Injection / Path Traversal Attack (1:30 – 2:30)

**Speaker Narration:**
> "Now, suppose the agent is manipulated via prompt injection or rogue LLM output to perform a path traversal attack: `../../../etc/passwd`.
> In an unprotected architecture, the tool would read the host file. Let's see what happens with AgentGuard."

**Screen Action / Demo Trigger:**
- Switch to the **Attack Lab** tab.
- Select **Scenario 3: Sensitive Resource Access / Path Traversal**.
- Click **Run Attack Scenario**.

**Speaker Narration:**
> "Look at the Gateway interception:
> - Parameter security inspection immediately detected `PATH_TRAVERSAL` and `SENSITIVE_RESOURCE`.
> - The Gateway short-circuits the pipeline with a **BLOCK** decision.
> - **Crucial invariant:** The sandbox was never invoked. Post-block execution is **strictly 0.00%**. No data was read, and an alert is recorded in the Incident Center."

---

### Act 3: Honey Asset Canary & Instant Quarantine (2:30 – 3:30)

**Speaker Narration:**
> "What if an adversary attempts a sophisticated privilege escalation or searches for credentials in memory?
> AgentGuard deploys active deception with synthetic **Honey Assets** and canary tokens."

**Screen Action / Demo Trigger:**
- In the **Attack Lab**, select **Scenario 5: Honey Asset Interaction** (`AG-HONEY-7F92-XK11`).
- Click **Run Attack Scenario**.

**Speaker Narration:**
> "The instant the agent touches the honey asset:
> 1. **Tripwire Triggers**: The Gateway identifies the canary signature `HONEY_ASSET_TOUCHED`.
> 2. **Immediate Quarantine**: The agent's security state transitions from `CLEAR` to `QUARANTINED`.
> 3. **Status Suspended**: The agent is suspended (`status: suspended`).
> 4. **Epoch Invalidation**: The agent's security epoch increments, instantly invalidating all existing cryptographic tokens.
> 
> Even if this compromised agent attempts further actions, every subsequent request is blocked at Step 1 of the Gateway."

---

### Act 4: Cryptographic Audit Ledger & Deterministic Replay (3:30 – 4:15)

**Speaker Narration:**
> "For enterprise compliance and forensic investigations, every single Gateway decision is hashed using RFC-8785 JSON Canonicalization and chained into an immutable SHA-256 Merkle ledger."

**Screen Action / Demo Trigger:**
- Switch to the **Checkpoints / Audit** tab.
- Click **Verify Audit Integrity**.
- Point to the verification result: `MERKLE CHAIN VERIFIED: True (100% Tamper-Proof)`.
- Point to the **Counterfactual Replay**:
> "We can also run counterfactual replays of any past trace to verify deterministic state reproducibility without re-triggering side effects."

---

### Act 5: Summary & Conclusion (4:15 – 5:00)

**Speaker Narration:**
> "To summarize, AgentGuard delivers:
> 1. **Zero Direct Authority**: Agents only propose actions; the Gateway authorizes and executes.
> 2. **Fail-Closed Isolation**: Network-isolated, capability-dropped sandbox containers.
> 3. **Active Deception**: Canary honeytokens that catch compromised agents red-handed.
> 4. **Immutable Auditability**: Cryptographic RFC-8785 Merkle chain verification.
> 
> Thank you, and we're ready for your questions!"

---

## Judge Q&A Cheat Sheet

| Question | Winning Answer |
|---|---|
| **"How do you stop an agent from bypassing the Gateway?"** | "Agents are given zero raw tool execution credentials or network socket access. Tools can only be invoked by the Gateway executor with internal capability keys. All agent calls must pass through the Gateway API with short-lived, task-bound cryptographic tokens." |
| **"Is the Docker sandbox escape-proof?"** | "We follow defense-in-depth: the sandbox is hardened with read-only root filesystems, dropped capabilities (`cap_drop: ALL`), non-root execution (`10001:10001`), `no-new-privileges`, seccomp filters, and `network_mode: none`. More importantly, malicious actions are blocked at the Gateway before reaching the sandbox." |
| **"What is the latency overhead of the Gateway?"** | "The core evaluation pipeline (token verification, parameter inspection, circuit breaker, and risk scoring) is purely in-memory and deterministic, taking under 2 milliseconds per request." |
| **"How do Human-in-the-Loop approvals work?"** | "For high-risk operations, the Gateway returns `REQUIRE_APPROVAL` with a cryptographic action fingerprint. An operator must review and approve with a fresh cryptographic token, ensuring parameters cannot be modified in flight." |
| **"How do you handle multi-agent swarms?"** | "AgentGuard tracks inter-agent communication boundaries. If one agent in the mesh is quarantined or trips a circuit breaker, its communication edges and tokens are invalidated, preventing lateral movement across the swarm." |
