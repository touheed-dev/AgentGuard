# AgentGuard Backend Engineering Plan

This plan implements PRD v2.4.1 without changing its locked architecture. The backend is a modular monolith: the Gateway owns the authorization pipeline and invokes typed in-process services. The executor is the only separate execution boundary.

## Delivery Rules

- Replay mode is the canonical path for CI and demos.
- PostgreSQL is authoritative for security state, decisions, approvals, incidents, traces, events, and audit data.
- Valkey is limited to live delivery, short-lived counters, and ephemeral coordination.
- All agent, orchestration, and LLM proposals enter the same Gateway.
- No tool implementation is importable from agents, orchestration, or API presentation code.
- Security decisions are deterministic and do not depend on an LLM.
- Each phase ends with tests, lint, type checking, security/invariant checks, and an updated status document.

## Target Layout

```text
backend/
  apps/gateway/
  core/{identity,capabilities,policy,validation,task_consistency,risk,behavior,sequence,decision,approval,breaker,audit,incidents}/
  services/{executor,llm_client,event_bus}/
  agents/{planner,researcher,coder,executor}/
  deception/{honeytool,honeytoken}/
  simulations/{attacks,replay}/
  shared/{schemas,events,contracts}/
  tests/
  infrastructure/{docker,postgres,valkey,compose}/
contracts/{openapi,schemas,events}/
docs/adr/
```

## Phase 0: Runnable Foundation

Deliver the Python 3.12+ project, environment settings, package boundaries, Compose services, health checks, shared Pydantic models, reason-code constants, OpenAPI export, and test tooling. Compose must start in replay mode without an API key or external network.

The first contracts are `ActionRequest`, `AgentProposal`, `Decision`, `Reason`, `Agent`, `Tool`, `Policy`, `Task`, `TraceEvent`, `Approval`, and `Incident`. JSON Schema files are generated from the same Pydantic definitions, never maintained separately by hand.

## Phase 1: Gateway Spine

Implement the clearly ordered Gateway pipeline. Stages 1-6 short-circuit to `BLOCK`; verified requests still receive the honey-asset scan. Add Ed25519 token issuance and verification, agent/capability registries, exact tool lookup, basic declarative policy evaluation, and a stub executor reachable only through the Gateway.

Required proof: an agent can perform one allowed registered action, an unknown or unauthorized action is blocked, and no tool execution occurs without a prior authorization record.

## Phase 2: Persistence and Events

Phase 1 is complete. The Gateway spine now owns Ed25519 token verification, in-memory registries, declared capability checks, exact tool resolution, basic object-schema validation, deterministic decisions, and a one-time fingerprint-bound grant executor. These behaviors remain the baseline for Phase 2.

Phase 2 foundation is implemented for agents, tools, tasks, executions, audit chain state/events, and outbox events. SQLAlchemy 2 async models, repositories, Alembic upgrade/downgrade wiring, RFC 8785 audit verification, persistence-aware lifecycle coordination, PostgreSQL advisory locking, append-only migration triggers, and a replay-safe Valkey adapter are present. The synchronous Gateway still uses its Phase 1 in-memory registries; repository-backed registry hydration, the publication worker, PostgreSQL roles/grants, live container validation, and SSE delivery are explicitly deferred.

## Phase 3: Deterministic Security Evaluation

Add normalized parameter validation for paths, symlinks, secrets/configuration, commands, URLs, private IPs, DNS rebinding, payload limits, SQL, execution flags, encoding, destinations, and scope. Add task consistency, behavior/sequence signals, risk factors and cumulative risk, hard-signal floors, stable reason codes, and restrictive decision precedence.

## Phase 4: Agents and Replay

Implement scripted Planner, Researcher, Coder, and Executor agents that can only submit proposals through typed Gateway interfaces. Add a persistent async orchestrator, deterministic clock/ID providers, trace fixtures, and replay comparison using exact hashes where possible and normalized trace hashes otherwise.

## Phase 5: Containment and Human Control

Add PostgreSQL-backed approval state transitions, redacted structural approval payloads, action fingerprints and freshness checks, execution idempotency, circuit breaker persistence, incidents, quarantine, HoneyTool, Honeytoken, and communication-graph enforcement. Honey references must be detected even on early capability denial, with zero tool execution.

## Phase 6: Frontend Contract Surface

Finalize REST endpoints and generated OpenAPI. Define SSE event schemas, pagination/filtering behavior, redaction guarantees, and replay/trace payloads for the separate dashboard team. Do not place security decisions in the frontend.

## Phase 7: Attack Lab and CI

Implement the six P0 attack scenarios. Each produces a decision, stable reason codes, incident, trace, replay fixture, and audit evidence. Add the full regression suite and architectural checks for direct tool, HTTP, filesystem, database, Docker, and network access from agents and orchestrators.

## Phase 8: Docker Executor

Implement the Docker SDK executor with the PRD profile: read-only root, disabled network, non-root UID/GID, dropped capabilities, no-new-privileges, seccomp, process/memory/CPU limits, no Docker socket, isolated workspace, timeout, and explicit result/unknown-result handling. Document that P0 is constrained demonstration isolation, not escape-proof isolation.

## Shared Contracts and API Ownership

Backend owns `contracts/openapi/openapi.json`, JSON Schemas under `contracts/schemas/`, and typed event schemas under `contracts/events/`. Public action execution must expose lifecycle state, execution/idempotency identifiers, exactly one decision, stable reasons, risk breakdown, policy/capability/parameter results, and redacted data only.

## Persistence Model

The authoritative schema includes `agents`, `tools`, `policies`, `tasks`, `events`, `incidents`, `approvals`, `traces`, `violations`, `agent_communications`, `risk_assessments`, `honey_assets`, `checkpoints`, and `executions`. Add indexes for trace reconstruction, incident queries, approval queues, event streams, audit verification, and idempotency uniqueness.

## Security and Test Gates

Every phase must test the negative path first: invalid tokens, wrong audience, expiration, task mismatch, stale capability version, suspended/quarantined agents, replayed request IDs, unknown and near-named tools, widened scope, forbidden destinations, invalid communication, stale approvals, duplicate idempotency keys, lost results, audit tampering, and Valkey outage.

Architectural tests must fail if agent/orchestrator code imports tool implementations or uses direct HTTP, filesystem, database, Docker, or arbitrary network access. Critical tools fail closed on internal errors. Attack Lab post-block execution rate must remain zero.

## Team and Change Control

The Integration Owner controls `shared/`, contracts, dependency order, ADRs, Compose health checks, and replay-suite merge gates. No shared schema changes land without versioning, tests, and an ADR when architecture changes. This workspace currently has no Git history, so repository initialization is a Phase 0 prerequisite.

## Definition of Done

A backend phase is complete only when its implementation, tests, API/schema documentation, failure behavior, replay behavior, security invariants, and status update are present and the complete runnable foundation remains healthy.
