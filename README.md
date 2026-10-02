# AgentGuard

**AgentGuard** is an autonomous AI agent runtime security gateway, policy enforcement engine, and containment platform designed to enforce fail-closed security invariants at execution boundaries.

---

## Key Capabilities

1. **Deterministic Security Gateway**:
   - **Identity & Capability Scoping**: Asymmetric cryptographic token verification with agent and task identity binding, scoped tool permissions, and security epoch invalidation.
   - **Circuit Breaker Enforcement**: Multi-tier severity escalation tracking (warning thresholds, high-risk suspension, and immediate fail-closed critical isolation).
   - **Input Validation & Sanitization**: Deterministic inspection for path traversal (`../`), private IP/SSRF addresses (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.1`), and prompt injection patterns.
   - **Honey Asset Canaries**: Synthetic honeytoken and canary resource detection triggering immediate agent quarantine and security epoch revocation.
   - **Dual-Token Human-in-the-Loop Approvals**: Cryptographic action fingerprinting and freshness tokens for sensitive operations.
   - **Cryptographic Audit Ledger**: RFC-8785 JSON Canonicalization (JCS) and SHA-256 Merkle hash chain verification.

2. **Hardened Docker Sandbox Execution**:
   - Isolated execution boundary with read-only root filesystems, dropped Linux capabilities (`cap_drop: ALL`), non-root UID (`10001:10001`), `no-new-privileges`, seccomp profiles, and disabled networking (`network_mode: none`).
   - Strict lifecycle tracking: `REQUESTED` → `AUTHORIZED` → `EXECUTING` → `SUCCEEDED` / `FAILED` / `UNKNOWN_RESULT`.

3. **Attack Lab**:
   - 6 reproducible threat scenarios verified through live Gateway APIs:
     1. **Prompt Injection / Argument Tampering** (Blocked at parameter inspection)
     2. **Capability Violation** (Blocked by capability enforcement)
     3. **Sensitive Resource Access / Path Traversal** (Blocked at resource validation)
     4. **Unsafe Destination / SSRF** (Blocked at network boundary check)
     5. **Honey Asset Interaction** (Quarantined with epoch rotation)
     6. **Cumulative Risk Escalation** (Circuit breaker tripped with agent suspension)

4. **Persistent Trace & Attack Graph**:
   - End-to-end trace correlation linking agents, tasks, actions, decisions, tools, executions, incidents, risks, and agent-to-agent communications.
   - Topological graph modeling and export for attack path visualization.

5. **LLM Gateway Abstraction**:
   - Provider abstraction supporting **Groq** (live cloud LLM), **Ollama** (local LLM), and deterministic **Replay** engine.
   - Strict API key isolation: credentials never reach agents, tools, frontend clients, or sandbox containers.
   - Pre-egress secret redaction and token rate budgeting.

6. **Interactive Full-Stack Command Center**:
   - High-performance dashboard built with React, Vite, TypeScript, and Tailwind CSS.
   - Real-time views:
     - **Command Center**: Posture metrics, active agents, circuit breaker states.
     - **Live Activity**: Event stream and telemetry feed.
     - **Agent Graph**: Topological map of agent communication and tool access.
     - **Incident Center**: High and critical security incident management.
     - **Approval Center**: Pending human-in-the-loop authorization queue.
     - **Attack Lab**: Interactive runner for threat scenarios and counterfactual replays.

---

## Architecture Overview

```text
Autonomous Agent / LLM
         │
         │ (Tool Execution Request)
         ▼
┌─────────────────────────────────────────────────────────────┐
│                   AgentGuard Gateway                         │
│                                                             │
│  [1. Token & Identity Verification (Ed25519 / Epoch)]       │
│  [2. Circuit Breaker Check (Tripwire / Suspension)]         │
│  [3. Honey Asset & Canary Detection]                        │
│  [4. Capability & Scope Validation]                         │
│  [5. Parameter Security & Schema Validation]                │
│  [6. Dynamic Risk & CEL Policy Assessment]                  │
│  [7. Human-in-the-Loop Dual-Token Approval (if required)]   │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ Decision: BLOCK ]             [ Decision: ALLOW ]
               │                               │
        Fail-Closed Exit                       ▼
        (0.00% Execution)          ┌───────────────────────┐
               │                   │ Hardened Sandbox /    │
               │                   │ Isolated Tool Exec    │
               │                   └───────────┬───────────┘
               │                               │
               └───────────────┬───────────────┘
                               ▼
            ┌─────────────────────────────────────┐
            │   RFC-8785 Merkle Audit Ledger      │
            │   PostgreSQL + Valkey Persistence   │
            └─────────────────────────────────────┘
```

---

## Prerequisites

- **Python**: 3.11+
- **Node.js**: 18+ (tested on Node.js 22)
- **Docker & Docker Compose**: (Recommended for full multi-container deployment)

---

## Quickstart

### Option A: Docker Compose (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/touheed-dev/AgentGuard.git
   cd AgentGuard
   ```

2. Start the services:
   ```bash
   docker compose up -d --build
   ```

3. Verify service health:
   ```bash
   curl -s http://localhost:8000/health
   ```

4. Launch the dashboard:
   ```bash
   cd frontend-teammate
   npm install
   npm run dev
   ```
   Open `http://localhost:5173` in your browser.

---

### Option B: Local Python Development

1. Environment setup:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate

   pip install -e .
   ```

2. Start the Gateway:
   ```bash
   uvicorn backend.apps.gateway.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. Start the Frontend:
   ```bash
   cd frontend-teammate
   npm install
   npm run dev
   ```

---

## Configuration & Modes

| Variable | Values | Description |
|---|---|---|
| `LLM_MODE` | `replay` (default) \| `live` \| `fallback` | LLM execution mode. Replay mode is deterministic and requires no external API keys. |
| `GROQ_API_KEY` | `gsk_...` | Groq API key for live provider mode. |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Model ID for Groq integration. |
| `AGENTGUARD_PERSISTENCE` | `true` \| `false` | Enables PostgreSQL state persistence and Valkey state tracking. |

---

## Verification & Testing

### 1. End-to-End Deterministic Demo Sequence
Verify the full security pipeline (ALLOW → BLOCK → Honey Asset Quarantine → Incident Record → Audit Chain → Replay):

```bash
python scripts/verify_demo_flow.py
```

### 2. P0 Automated Validation Harness
Run the 24-gate automated test and compliance harness:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/validate-p0.ps1
```

### 3. Backend Pytest Suite
Run the 93 unit and integration tests:

```bash
python -m pytest backend/tests -v
```

### 4. Frontend Typecheck & Production Build
```bash
cd frontend-teammate
npm run build
```

---

## Gateway API Surface

| Endpoint | Method | Description |
|---|---|---|
| `/health` | `GET` | Gateway service health and active LLM mode. |
| `/tokens/issue` | `POST` | Issue scoped asymmetric identity and capability tokens. |
| `/actions/evaluate` | `POST` | Authorize proposed tool actions through the stage-gate pipeline. |
| `/actions/execute` | `POST` | Atomically authorize and execute tool actions in isolation. |
| `/approvals` | `GET` | List pending human-in-the-loop approvals. |
| `/approvals/{id}/approve` | `POST` | Submit approval with cryptographic freshness token. |
| `/approvals/{id}/reject` | `POST` | Reject pending action. |
| `/incidents` | `GET` | Retrieve recorded security incidents. |
| `/audit/verify` | `GET` | Verify the cryptographic RFC-8785 Merkle audit chain. |
| `/agents` | `GET` | Agent inventory, status, and security states. |
| `/tools` | `GET` | Registered tool inventory and capability requirements. |
| `/traces` | `GET` | Execution traces with canonical trace hashes. |
| `/graph` | `GET` | Attack and agent topology graph. |
| `/activity` | `GET` | Live activity feed. |
| `/replay` | `POST` | Execute counterfactual deterministic replay of a trace. |
| `/attack-lab/run/{id}` | `POST` | Execute Attack Lab threat scenarios 1–6. |

---

## License

Apache-2.0
