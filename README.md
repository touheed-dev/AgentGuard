# AgentGuard

AgentGuard is an autonomous AI agent security gateway, policy enforcement runtime, and containment platform designed to secure agentic systems at execution boundaries.

Built strictly according to **AgentGuard PRD v2.4.1 (Architecture Lock)**.

---

## Key Features

1. **Deterministic Security Gateway**:
   - Identity verification with scoped cryptographic capabilities and security epochs.
   - Circuit breaker enforcement (rate & severity escalation: medium warning escalation, high-risk suspension, critical immediate block).
   - Parameter and security validation (path traversal, private IP/SSRF, injection defense).
   - Honey asset registry and honeytoken detection with automatic agent quarantine and epoch incrementation.
   - Dual-token human-in-the-loop approvals with cryptographic freshness fingerprints.
   - Immutable audit logging with SHA-256 hash chains.

2. **Hardened Docker Executor**:
   - Read-only root filesystem, isolated non-root user (`10001:10001`), network disabled.
   - Dropped Linux capabilities (`ALL`), `no-new-privileges`, seccomp isolation, tmpfs workspace, resource limits (CPU, memory, PID).
   - Execution lifecycle outcomes: `REQUESTED`, `AUTHORIZED`, `EXECUTING`, `SUCCEEDED`, `FAILED`, `UNKNOWN_RESULT`.

3. **Attack Lab**:
   - 6 reproducible P0 attack scenarios:
     1. Prompt Injection
     2. Capability Violation
     3. Sensitive Resource / Path Traversal
     4. Unsafe Destination / Private IP SSRF
     5. Honey Asset / Honeytoken Interaction
     6. Cumulative Risk Escalation & Circuit Breaker Suspension

4. **Persistent Trace & Attack Graph**:
   - Complete trace reconstruction connecting agents, tasks, actions, decisions, tools, executions, incidents, risks, and communications.
   - NetworkX attack graph modeling and subgraph extraction.

5. **LLM Gateway Abstraction**:
   - Provider abstraction supporting Groq (live provider), Ollama (local provider), and deterministic Replay.
   - Pre-egress secret redaction, token budgeting, and response caching.
   - API keys strictly isolated from agents, tools, frontend, and sandbox environments.

6. **Full-Featured Frontend Dashboard**:
   - Next.js (App Router), TypeScript, Tailwind CSS, Lucide-React.
   - 6 real-time operational views:
     - **Command Center**: Key posture metrics, active agents, circuit breaker states.
     - **Live Activity**: Real-time event and action feed.
     - **Agent Graph**: Topological map of agent communication and tool access.
     - **Incident Center**: High/critical alerts, triggered actions, and containment actions.
     - **Approval Center**: Pending human-in-the-loop decisions with authorization fingerprints.
     - **Attack Lab**: Interactive runner for the 6 core threat scenarios.

---

## Prerequisites

- **Python**: 3.11+ (tested on Python 3.14)
- **Node.js**: 18+ (tested on Node.js 22)
- **Docker & Docker Compose** (Optional for local live containers; mock executor active when Docker is unavailable)

---

## Quickstart

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/touheed-dev/AgentGuard.git
cd AgentGuard

# Python virtual environment setup
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install backend dependencies
pip install -e .
```

### 2. Backend Startup

```bash
# Start Gateway FastAPI application
uvicorn backend.apps.gateway.main:app --host 0.0.0.0 --port 8000 --reload
```

API documentation will be available at: `http://localhost:8000/docs`

### 3. Frontend Startup

```bash
cd Frontend
npm install
npm run dev
```

Dashboard will be accessible at: `http://localhost:3000`

---

## Testing & Verification

Run all test suites:

```bash
# Backend unit & integration tests (68+ tests)
python -m pytest backend/tests -v

# Run 22-step End-to-End Vertical Slice
python -m pytest backend/tests/test_phase11_demo_slice.py -v

# Validate Python compilation
python -m compileall -q backend scripts

# Re-export OpenAPI contracts
python scripts/export_openapi.py

# Frontend build & typecheck
cd Frontend
npm run build
```

---

## Attack Lab Scenarios

The Attack Lab scenarios run through the real Gateway:

```bash
# Run Attack Lab test suite
python -m pytest backend/tests/test_phase8_attack_lab.py -v
```

Scenarios:
- `prompt_injection`: Intercepted and blocked before execution.
- `capability_violation`: Blocked by Capability Registry enforcement.
- `path_traversal`: Sensitive resource access rejected with `PATH_TRAVERSAL`.
- `ssrf_attempt`: Unsafe private IP destinations blocked with `UNSAFE_DESTINATION`.
- `honey_asset`: Interacting with synthetic canary keys triggers immediate agent quarantine and security epoch bump.
- `risk_escalation`: Rapid suspicious events trip the circuit breaker and suspend the agent.

---

## Architecture Status

- **Phase 0**: Monorepo scaffolding, configuration, linters, pre-commit.
- **Phase 1**: Gateway core, Identity, Capability, Policy, Validation, Audit.
- **Phase 2**: PostgreSQL models, Alembic migrations, Outbox pattern, Valkey replay state.
- **Phase 3**: Dynamic Risk Engine, Risk scoring, tool sensitivity weighting.
- **Phase 4**: Side-effect-free Replay Engine, idempotency protection.
- **Phase 5**: Circuit Breaker enforcement, Agent-to-Agent communication boundaries, Human-in-the-loop approvals, Honey asset registry, Incident lifecycle.
- **Phase 6**: Hardened Docker Sandbox isolation profile.
- **Phase 7**: Trace and Attack Graph reconstruction service.
- **Phase 8**: P0 Attack Lab scenarios.
- **Phase 9**: Next.js App Router frontend dashboard.
- **Phase 10**: Backend OpenAPI contracts and generated TypeScript definitions.
- **Phase 11**: 22-step vertical slice end-to-end integration.
- **Phase 12**: LLM gateway client with Groq, Ollama, and Replay modes.

---

## License

Apache-2.0
