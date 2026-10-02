<div align="center">

<img src="docs/images/agentguard_banner.png" alt="AgentGuard — Secure AI Agents. Real-World Impact." width="580" />

<br />

### Zero-Trust Runtime Security Gateway for Autonomous AI Agents

> **Intercepts, authorizes, and controls every AI agent action before execution with deterministic CEL policies, active deception tripwires, dual-token human approval, hardened container isolation, and cryptographically verifiable Merkle audit trails.**

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Backend Tests: 93/93 Passed](https://img.shields.io/badge/Backend%20Tests-93%2F93%20Passed-047857.svg)](https://github.com/touheed-dev/AgentGuard)
[![P0 Gates: 24/24 Verified](https://img.shields.io/badge/P0%20Release%20Gates-24%2F24%20Verified-047857.svg)](https://github.com/touheed-dev/AgentGuard)
[![Post-Block Rate: 0.00%](https://img.shields.io/badge/Post--Block%20Exec%20Rate-0.00%25%20Fail--Closed-047857.svg)](https://github.com/touheed-dev/AgentGuard)
[![Vite Build: Clean](https://img.shields.io/badge/Frontend%20Build-Clean%20%28520ms%29-047857.svg)](https://github.com/touheed-dev/AgentGuard)

<p align="center">
  <b><a href="#-overview">Overview</a></b> •
  <b><a href="#-key-features">Key Features</a></b> •
  <b><a href="#-brand-identity--design-system">Brand Identity</a></b> •
  <b><a href="#-20-stage-security-pipeline">20-Stage Pipeline</a></b> •
  <b><a href="#-system-architecture--visual-schematics">Architecture</a></b> •
  <b><a href="#-tech-stack">Tech Stack</a></b> •
  <b><a href="#-quick-start">Quick Start</a></b> •
  <b><a href="#-judge-defense--viva-guide">Judge Defense</a></b>
</p>

</div>

---

## 📖 Table of Contents

- [📌 Overview](#-overview)
- [🌟 Key Features](#-key-features)
- [🎨 Brand Identity & Design System](#-brand-identity--design-system)
- [⚙️ 20-Stage Security Pipeline](#-20-stage-security-pipeline)
- [🏗️ System Architecture & Visual Schematics](#-system-architecture--visual-schematics)
- [💻 Tech Stack](#-tech-stack)
- [📁 Project Directory Structure](#-project-directory-structure)
- [🔌 API Specification & REST Contracts](#-api-specification--rest-contracts)
- [🧪 Attack Lab & Threat Scenarios](#-attack-lab--threat-scenarios)
- [🚀 Quick Start & Setup](#-quick-start)
- [🎓 Judge Defense & Viva Guide](#-judge-defense--viva-guide)
- [🛡️ Verification Suite & Code Quality](#-verification-suite--code-quality)
- [📄 License](#-license)

---

## 📌 Overview

Autonomous AI agents possess ambient authority and expansive tool permissions. When an agent experiences **prompt injection, semantic goal hijacking, sub-goal drift, or tool-parameter poisoning**, standard application firewalls cannot differentiate between genuine agent planning and adversarial manipulation.

**AgentGuard solves this fundamental vulnerability by operating as a transparent, inline zero-trust gateway**:

```text
Autonomous AI Agent (LLM)
           │
           │ [Proposes Action: tool_name, arguments, task_id]
           ▼
┌─────────────────────────────────────────────────────────────┐
│                   AGENTGUARD GATEWAY                        │
│                                                             │
│  1. Cryptographic Identity & Delegation Verification         │
│  2. Fail-Closed Circuit Breaker & Blast-Radius Check        │
│  3. Synthetic Canary / HoneyAsset Tripwire Inspection        │
│  4. Deterministic Parameter Sanitization (Path, SSRF, SQL)   │
│  5. Common Expression Language (CEL) Deterministic Rules    │
│  6. Multi-Factor Composite Risk Assessment (0–100 Score)    │
│  7. Dual-Token Step-Up Human Authorization (Quarantine)      │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ Decision: BLOCK ]             [ Decision: ALLOW ]
               │                               │
        Fail-Closed Exit                       ▼
        (0.00% Execution)          ┌───────────────────────┐
               │                   │ Hardened Docker       │
               │                   │ Sandbox Execution     │
               │                   └───────────┬───────────┘
               │                               │
               └───────────────┬───────────────┘
                               ▼
            ┌─────────────────────────────────────┐
            │   RFC-8785 Merkle Audit Ledger      │
            │   SHA-256 Hash Chain Verification   │
            └─────────────────────────────────────┘
```

* **Zero Execution Bypass**: Tools, APIs, and credentials can only be accessed through the Gateway's authenticated proxy. Direct unmonitored execution is architecturally impossible.
* **Measured Pre-Execution Latency**: In-memory deterministic CEL policy evaluation operates in **under 2ms**.
* **Measured Post-Block Execution Rate**: **0.00%** across all tested adversarial payloads.

---

## 🌟 Key Features

### 1. 🛡️ Deterministic 4-Verdict Decision Engine
Every intercepted agent action proposal evaluates to exactly one immutable verdict:
* **`ALLOW`**: Validated credentials, parameters within safe boundary, risk score below threshold. Action forwards to execution sandbox.
* **`WARN`**: Minor scope anomaly or elevated observation flag. Telemetry logged; execution permitted with audit tag.
* **`REQUIRE_APPROVAL`**: High-risk mutating action (e.g., database wipe, external transfer). Action placed in Quarantine Cockpit until signed by authorized human operator.
* **`BLOCK`**: Threat detected (path traversal, SSRF, injection, canary breach). Execution halted immediately before payload touches operating system.

### 2. 🍯 Active Deception & HoneyAsset Tripwires
* Deploys synthetic canary API keys, fake file paths (`/etc/shadow.bak`, `honey_token.key`), and decoy database records.
* Any agent reading or invoking a honey asset trips an instant severity incident, rotates the agent's security epoch, and applies **instant automatic quarantine**.

### 3. ⚡ Circuit Breaker & Automatic Quarantine
* Tracks cumulative agent anomaly scores across sliding time windows.
* Triggers automatic circuit trip when repeated violations occur, isolating the rogue agent and preventing cascading mesh compromises.

### 4. 🔒 Hardened Docker Execution Sandbox
* Actions authorized for execution run in an ephemeral container boundary:
  * Non-root user execution (`UID 10001:10001`)
  * Read-only root filesystem (`read_only: true`)
  * Dropped Linux capabilities (`cap_drop: ALL`)
  * Privilege escalation blocked (`no-new-privileges: true`)
  * Ephemeral tmpfs (`/tmp:size=64M`)
  * Strict CPU (0.5 cores) and memory (256MB) quotas

### 5. 📜 RFC-8785 Merkle Audit Chain
* Every decision, action hash, and state transition is canonicalized via **RFC-8785 JSON Canonicalization (JCS)**.
* Appended to an immutable SHA-256 cryptographic ledger with real-time Merkle root verification (`GET /audit/verify-chain`).

### 6. 🔄 Deterministic Trace Replay & Counterfactual "What-If" Analysis
* Replay historical attack traces against modified CEL rule sets without re-executing dangerous payloads.
* Proves mathematical policy efficacy against past incident recordings.

### 7. ⏱️ 1-Click Deterministic Demo Reset (`POST /demo/reset`)
* Complete zero-state reset clearing active incidents, restoring honey assets, re-enabling quarantined agents, and resetting the trace graph for reproducible live demonstrations.

---

## 🎨 Brand Identity & Design System

AgentGuard features a bespoke **Warm Tactical Cyber** design identity — balancing Swiss minimalism, editorial typography, and high-contrast security command center aesthetics:

<div align="center">
  <img src="docs/images/agentguard_shield.png" alt="AgentGuard Shield Emblem" width="160" />
  <p><sub><b>The AgentGuard Security Shield with Central Agent 'A' Chevron & Intelligence Spark Star</b></sub></p>
</div>

### 🏷️ Design Concept & Philosophy
* **The Shield Emblem**: Hexagonal dual-facet shield representing security.
  * **Left Facet**: Deep rich emerald/teal gradient (`#044E3F` → `#047857` → `#065F46`).
  * **Right Facet**: Warm champagne / stone gold gradient (`#E2DCD1` → `#C5BBAE` → `#9E9284`).
* **The 'A' Chevron**: Obsidian Charcoal (`#1E232A` / `#2D333B`) forming the upward agent chevron.
* **Core Spark Star**: 4-point diamond star in luminous emerald teal (`#10B981` / `#047857`) nestled at the base, symbolizing trusted, aligned artificial intelligence.
* **Brand Wordmark**: **Agent** (`#1E232A`) + **Guard** (`#047857`).
* **Official Tagline**: `SECURE AI AGENTS. REAL-WORLD IMPACT.`
* **Core Pillars**: `SECURITY · CONTROL · OBSERVABILITY · TRUST`.

### 🎨 Color Palette Tokens

```css
:root {
  --bg-sand:       #F5F0E8; /* Warm Sand Canvas Background */
  --surface-stone: #EDE8DE; /* Frosted Stone Card Surface (Glassmorphism) */
  --input-cream:   #FAF7F2; /* Off-White Input Wells & Code Blocks */
  --text-charcoal: #1E232A; /* Obsidian Charcoal Primary Typography */
  --text-muted:    #7A6F62; /* Muted Sepia Subtitles & Metadata */
  --border-line:   #D6CFC3; /* Warm Platinum 1px Connected Border Grid */

  /* Security Status Badges */
  --allow-emerald: #047857; /* ALLOW / Safe Verification / Live Badge */
  --warn-amber:    #B45309; /* WARN / Caution / Elevated Observation */
  --block-red:     #B91C1C; /* BLOCK / Critical Threat / Canary Breach */
  --approval-purp: #6D28D9; /* REQUIRE_APPROVAL / Human Quarantine */
}
```

### 🔤 Typography Stack
* **Display & Headings**: `Space Grotesk` (Technical, geometric sans-serif)
* **Body & UI**: `Inter` (Crisp, high-legibility interface copy)
* **Terminal & Code**: `JetBrains Mono` (Cryptographic hashes, payloads, JSON)

---

## ⚙️ 20-Stage Security Pipeline

Every agent invocation is evaluated through 20 deterministic inspection gates before touching system resources:

![Gateway Pipeline Flow](docs/images/gateway_pipeline_flow.png)

```text
 1. Request Envelope Integrity Check  ──► [ Fail-Closed on Malformed JSON ]
 2. Asymmetric Ed25519 Token Decrypt   ──► [ Verify Signature & Epoch Freshness ]
 3. Agent Identity & Role Validation   ──► [ Validate Agent State != QUARANTINED ]
 4. Circuit Breaker Blast Radius Gate ──► [ Check Consecutive Anomaly Score ]
 5. Task & Scope Context Binding      ──► [ Verify Action Belongs to Assigned Task ]
 6. Delegation Depth Cap (Depth <= 3) ──► [ Block Recursive Sub-Agent Hijacking ]
 7. Tool Inventory & Permission Match ──► [ Check Tool Exists & Agent is Permitted ]
 8. HoneyAsset Canary Detection       ──► [ Trap Honeytokens -> Immediate Quarantine ]
 9. Path Traversal Inspection         ──► [ Reject '../', '~/', '\..\', Encoded Slashes ]
10. SSRF & Private IP Filter          ──► [ Block 127.0.0.1, 10.0.0.0/8, 169.254.169.254 ]
11. Command & Shell Injection Filter  ──► [ Block ';', '&&', '`', '$(', '|', 'sudo' ]
12. SQL Injection Pattern Scanner     ──► [ Reject 'UNION SELECT', 'OR 1=1', '--' ]
13. Outbound Egress Whitelist Check   ──► [ Block Unapproved Destination Domains ]
14. Semantic Task Consistency Check   ──► [ Jaccard Keyword Drift vs Task Objective ]
15. Dynamic CEL Policy Evaluation     ──► [ In-Memory Deterministic Rule Set (<2ms) ]
16. Composite Risk Score Engine       ──► [ Compute Multi-Factor Risk (0-100) ]
17. Step-Up Approval Determination    ──► [ Risk >= 80 -> Route to Human Quarantine ]
18. Sandbox Container Policy Profile  ──► [ Apply Read-Only Root, Cap-Drop, Non-Root ]
19. Pre-Execution Merkle Log Append   ──► [ SHA-256 Canonical RFC-8785 Entry ]
20. Execution Dispatch & Secret Proxy ──► [ Inject Ephemeral Credential -> Run Sandbox ]
```

---

## 🏗️ System Architecture & Visual Schematics

### 1. High-Level Modular Monolith
![Architecture Schematic](docs/images/architecture_schematic.png)

### 2. Deception & Quarantine Workflow
![Deception Quarantine Workflow](docs/images/deception_quarantine_workflow.png)

### 3. Merkle Audit & Replay Engine
![Merkle Audit Replay Schematic](docs/images/merkle_audit_replay_schematic.png)

---

## 💻 Tech Stack

| Domain | Technology | Implementation Detail |
|---|---|---|
| **Backend Framework** | **Python 3.11 + FastAPI** | Asynchronous, type-safe API with Pydantic v2 schemas and compileall validation |
| **Policy Engine** | **Google CEL (cel-python)** | Deterministic, in-memory Common Expression Language rule evaluator |
| **Cryptography** | **Ed25519 + RFC-8785 (JCS)** | Asymmetric token signatures, canonical JSON hashing, and SHA-256 Merkle chaining |
| **Execution Sandbox** | **Docker Engine** | Non-root `UID 10001`, `read_only` rootfs, `cap_drop ALL`, `no-new-privileges`, tmpfs |
| **Persistence & Cache** | **PostgreSQL 16 + Valkey 8** | ACID event logging, state tracking, circuit breaker rate-limiting bus |
| **LLM Orchestration** | **Groq Cloud API + Simulation** | Live `llama-3.3-70b-versatile` reasoning + local deterministic simulation models |
| **Frontend Dashboard** | **Vite 8 + React 18 + TS** | Real-time command center, Lucide icons, Tailwind CSS, 520ms production build |
| **Telemetry & Testing** | **Pytest + PowerShell Harness** | 93 unit/integration tests, 24 automated P0 verification compliance gates |

---

## 📁 Project Directory Structure

```text
AgentGuard/
│
├── .env.example                       # Documented environment variable template
├── .gitignore                          # Clean git ignore (excludes secrets, venvs, caches)
├── Dockerfile                          # Multi-stage production container definition
├── docker-compose.yml                  # Gateway, PostgreSQL, and Valkey stack
├── pyproject.toml                      # Python dependencies and packaging manifest
├── alembic.ini                         # Database migration configuration
├── README.md                           # Comprehensive documentation & defense guide
│
├── backend/                            # Core Security Gateway Implementation
│   ├── agents/                         # Agent mesh definition, roles, and state machines
│   ├── apps/                           # FastAPI gateway entry point and routes
│   │   └── gateway/                    # Main app, dependencies, and WS streaming
│   ├── core/                           # Security Kernel
│   │   ├── audit/                      # Merkle tree, RFC-8785 canonical hash chaining
│   │   ├── breaker/                    # Circuit breaker, anomaly trackers, thresholds
│   │   ├── capability/                 # Ed25519 capability tokens, delegation depth
│   │   ├── deception/                  # Honeytokens, canary files, tripwire listeners
│   │   ├── identity/                   # Agent credentials, public keys, epoch rotation
│   │   ├── policy/                     # CEL policy engine and rule definitions
│   │   ├── risk/                       # Multi-factor composite risk calculator
│   │   └── validation/                 # Parameter sanitizers (Path, SSRF, Injection)
│   ├── infrastructure/                 # Docker executor, sandbox profiles, DB adapters
│   ├── services/                       # Orchestrator, live Groq LLM integration
│   ├── shared/                         # Common models, enums, exceptions, schemas
│   ├── simulations/                    # Attack lab fixtures and swarm generator
│   └── tests/                          # 93 Unit and integration Pytest suite
│
├── contracts/                          # Public Interface Contracts
│   ├── openapi/                        # Exported openapi.json with demo reset endpoints
│   └── schemas/                        # JSON schema definitions
│
├── frontend-teammate/                  # Official Live Dashboard (Vite + React SPA)
│   ├── index.html                      # HTML root with fonts & brand favicon
│   ├── package.json                    # Frontend dependencies & scripts
│   ├── tsconfig.json                   # TypeScript strict compiler options
│   ├── vite.config.ts                  # Vite build and proxy configuration
│   ├── public/                         # Vector favicon and static assets
│   └── src/                            # Dashboard Source Code
│       ├── App.tsx                     # Top-level state, WS stream, and toast manager
│       ├── api.ts                      # Centralized REST and WebSocket API client
│       ├── index.css                   # Warm Tactical Cyber design system
│       ├── types.ts                    # TypeScript domain interfaces
│       └── components/                 # UI Views & Widgets
│           ├── BrandLogo.tsx           # Official shield emblem & wordmark lockup
│           ├── Navbar.tsx              # Top navigation, ticker, live WS status, reset
│           ├── KpiTiles.tsx            # Animated KPI telemetry vouchers
│           ├── TelemetryChart.tsx      # Real-time trace telemetry vector
│           ├── CommandCenterView.tsx   # Pre-execution stream, agent mesh, approvals
│           ├── PipelineDeepDiveView.tsx# Interactive 20-stage step-through simulator
│           ├── AttackLabView.tsx       # Threat scenarios & counterfactual replay
│           ├── CheckpointsView.tsx     # Invariant verification & snapshot ledger
│           └── EventDetailDrawer.tsx   # Deep inspection drawer for intercepted events
│
├── docs/                               # Presentation & Defense Documentation
│   ├── ARCHITECTURE_DIAGRAMS.md        # Technical architecture specifications
│   ├── DEMO_SCRIPT.md                  # 10-Minute live presentation battle plan
│   ├── JUDGE_QA_DEFENSE.md             # Antigravity judge Q&A & anti-overclaim rules
│   ├── adr/                            # Architecture Decision Records (ADRs 001-007)
│   └── images/                         # High-res diagrams & brand identity PNGs
│       ├── brand_identity_system.png   # Official brand identity & color tokens
│       ├── architecture_schematic.png  # Modular monolith architecture
│       ├── gateway_pipeline_flow.png   # 20-stage gateway pipeline
│       ├── deception_quarantine_workflow.png # Canary tripwire flow
│       └── merkle_audit_replay_schematic.png # Merkle chain & replay
│
└── scripts/                            # Automation & Verification Harnesses
    ├── export_openapi.py               # Exports OpenAPI schema from FastAPI
    ├── preflight.ps1                   # Environment and port readiness check
    ├── test_live_groq_single.py        # Diagnostic live Groq LLM verification
    ├── validate-p0.ps1                 # 24-gate automated P0 verification harness
    └── verify_demo_flow.py             # 5-step deterministic E2E demo runner
```

---

## 🔌 API Specification & REST Contracts

All endpoints enforce strict schema validation via Pydantic v2. Interactive Swagger UI is available at `/docs`.

| Operation | HTTP Verb | Endpoint | Description |
|---|---|---|---|
| **Health** | `GET` | `/health` | Gateway status, active LLM mode, and ledger height |
| **Evaluate Action** | `POST` | `/actions/evaluate` | Intercepts proposed action; returns `ALLOW`, `WARN`, `REQUIRE_APPROVAL`, or `BLOCK` |
| **Execute Action** | `POST` | `/actions/execute` | Atomic authorization and isolated execution inside Docker sandbox |
| **Issue Token** | `POST` | `/tokens/issue` | Mints Ed25519 capability token bound to agent ID and task scope |
| **List Approvals** | `GET` | `/approvals` | Fetches pending quarantined actions requiring human authorization |
| **Resolve Approval**| `POST` | `/approvals/{id}/resolve` | Cryptographically approves (`APPROVE`) or cancels (`REJECT`) held action |
| **List Agents** | `GET` | `/agents` | Retrieves agent mesh inventory, status, and anomaly scores |
| **Quarantine Agent**| `POST` | `/agents/{id}/quarantine` | Forces instant containment and revokes current token epoch |
| **Reset Agent** | `POST` | `/agents/{id}/reset` | Restores quarantined agent to `HEALTHY` status |
| **Bump Epoch** | `POST` | `/agents/{id}/bump-epoch` | Invalidates all existing active tokens for target agent |
| **Verify Audit** | `GET` | `/audit/verify-chain` | Cryptographically validates SHA-256 Merkle chain integrity |
| **List Incidents** | `GET` | `/incidents` | Retrieves high/critical security breach records and forensic traces |
| **Run Scenario** | `POST` | `/attack-lab/scenarios/{id}/run`| Executes automated Attack Lab threat scenario |
| **Replay Trace** | `POST` | `/audit/replay` | Performs counterfactual deterministic replay of historical trace |
| **Reset Demo** | `POST` | `/demo/reset` | Resets all Gateway state, agents, and incidents to clean baseline |

---

## 🧪 Attack Lab & Threat Scenarios

AgentGuard includes 6 automated, reproducible threat scenarios in the **Attack Lab**:

| Scenario ID | Attack Vector | Target / Payload | Expected Decision | Defensive Mechanism |
|---|---|---|---|---|
| `SCN-01` | **Credential Exfiltration** | `http_fetch` to unwhitelisted external webhook | `BLOCK` | SSRF / Egress Domain Whitelist Filter |
| `SCN-02` | **Arbitrary Shell Execution**| `bash_exec` with command injection (`rm -rf; curl`) | `BLOCK` | Shell Metacharacter & Syntax Sanitizer |
| `SCN-03` | **Path Traversal / Secret Read**| `file_read` accessing `/etc/shadow` / `../../.env` | `BLOCK` | Canonical Path Boundary Inspector |
| `SCN-04` | **Honeytoken Canary Breach** | `file_read` on synthetic canary `/keys/honey_token.key`| `BLOCK` + `QUARANTINE` | Canary Tripwire -> Automatic Epoch Rotation |
| `SCN-05` | **High-Risk Production Mutation**| `db_query` executing `DROP TABLE users;` | `REQUIRE_APPROVAL` | High-Risk Mutation Quarantine Gate |
| `SCN-06` | **Legitimate Read Action** | `file_read` on sanitized `/data/reports/summary.txt` | `ALLOW` | Safe Capability Verification & Low Risk |

---

## 🚀 Quick Start

### Prerequisites
* **Python**: 3.11 or higher
* **Node.js**: 18 or higher (tested on Node 22)
* **Docker & Docker Compose**: (Required for container sandbox and production stack)

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/touheed-dev/AgentGuard.git
cd AgentGuard
```

### Step 2: Configure Environment
```bash
cp .env.example .env
```
*(Optional: Set `GROQ_API_KEY=gsk_...` in `.env` to enable live cloud LLM reasoning. By default, deterministic Replay mode runs with zero external API keys).*

### Step 3: Start the Backend (Docker Compose)
```bash
docker compose up -d --build
```
*Verify backend health:*
```bash
curl http://localhost:8000/health
```

### Step 4: Launch the Frontend Dashboard
```bash
cd frontend-teammate
npm install
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser to interact with the live Command Center.

---

## 🎓 Judge Defense & Viva Guide

### Frequently Asked Judge / Viva Questions

#### Q1: "Where does the interception happen? Can an agent bypass the gateway?"
> **Answer**: No. Direct tool execution is architecturally impossible. AgentGuard acts as a **credential and execution proxy**. Tools and execution environments do not accept commands directly from agents; they only accept commands bearing a valid, unexpired, cryptographic Gateway Dispatch Token issued after all 20 pipeline stages evaluate to `ALLOW`. If the Gateway fails or crashes, the request fails closed (zero execution).

#### Q2: "How does AgentGuard prevent performance bottlenecks on high-frequency agent actions?"
> **Answer**: Stage 1 through Stage 16 (CEL policy evaluation, parameter regex scanning, token verification, and risk computation) run **in-memory in under 2ms**. Database logging and Merkle audit appends occur asynchronously on an in-memory event bus backed by Valkey, ensuring high-throughput agent execution without blocking.

#### Q3: "What happens when an agent touches a HoneyAsset?"
> **Answer**: Active deception tripwires are embedded into tool parameters and file listings. When an agent attempts to access a honeytoken (e.g. `/keys/honey_token.key`), the Gateway immediately halts the action, logs a Critical Incident, invalidates the agent's current cryptographic token epoch, and transitions the agent's state to `QUARANTINED`—preventing any further tool calls across the entire mesh.

#### Q4: "How does the dual-token human approval workflow work?"
> **Answer**: When an action scores high risk (e.g. `DROP TABLE`), the Gateway generates an approval item with a cryptographic Action Fingerprint and holds the action in a quarantined state. An authorized operator reviews the exact action payload in the Approval Cockpit and signs the resolution (`APPROVE` or `REJECT`). If approved, an ephemeral single-use execution token is released.

#### Q5: "What is counterfactual replay?"
> **Answer**: Counterfactual replay allows security teams to take historical incident traces and re-evaluate them against updated CEL policies without re-executing payloads. This proves whether a tightened rule would have blocked an attack before deploying the rule live.

---

## 🛡️ Verification Suite & Code Quality

AgentGuard enforces strict, reproducible verification gates before any release:

```powershell
# 1. Run all 93 backend unit and integration tests
python -m pytest backend/tests -v

# 2. Run the 24-gate automated P0 verification harness
powershell -ExecutionPolicy Bypass -File scripts/validate-p0.ps1

# 3. Run the deterministic 5-step E2E demo sequence
python scripts/verify_demo_flow.py

# 4. Run frontend production build
cd frontend-teammate && npm run build
```

### Verification Results Summary:
* ✅ **93/93 Backend Pytest Tests Passing** (Unit, Integration, Security Kernel, CEL, Merkle Audit)
* ✅ **24/24 Automated P0 Release Gates Verified** (`scripts/validate-p0.ps1`)
* ✅ **5/5 E2E Demo Steps Deterministically Verified** (`scripts/verify_demo_flow.py`)
* ✅ **Clean Frontend Production Build**: `tsc -b && vite build` builds in **520ms** with 0 errors.

---

## 📄 License

This project is open-source software licensed under the **[Apache-2.0 License](LICENSE)**.
Feel free to use it for research, production deployments, and hackathon showcases.
