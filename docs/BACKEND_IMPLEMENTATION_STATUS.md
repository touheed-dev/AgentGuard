# AgentGuard Backend Implementation Status

**Baseline:** 2026-10-02  
**Source of truth:** `AgentGuard — PRD v2.4.1 (Architecture Lock).md`  
**Scope:** Backend and security/control plane only

## Audit Summary

The initial audit found only the authoritative PRD. Phase 0 and the Phase 1 deterministic Gateway spine now exist; persistence and later control-plane modules remain deferred.

The repository is now at the end of Phase 1 and is ready for a Phase 2 persistence checkpoint.

## Current Architecture

The implemented slice is a Python 3.12+ modular monolith with a FastAPI Gateway, deterministic Phase 1 security kernel, SQLAlchemy persistence foundation, RFC 8785 audit chain, transactional outbox records, and a replay-safe Valkey adapter. PostgreSQL is the configured authoritative runtime; live containers were not available during this validation.

## Implemented Features

Phase 0 foundation: shared Pydantic contracts, FastAPI health endpoint, replay-mode Compose services, OpenAPI export, seven JSON Schema exports, and test tooling.

Phase 1: Ed25519 token issuance/verification, agent registry, lifecycle/security-state checks, capability enforcement including declared tool capabilities, exact tool registry, basic object-schema validation, deterministic `Gateway.authorize()`, evaluate/execute endpoints, and a stub executor that accepts only one-time Gateway-issued ALLOW/WARN grants.

Phase 2: SQLAlchemy models and repositories for agents, tools, tasks, executions, audit chain state/events, and outbox events; Alembic upgrade/downgrade migration; exact RFC 8785/SHA-256 chain verification; persistence-aware action lifecycle; idempotency lookup; structured `/audit/verify`; and replay-safe Valkey configuration.

Phase 3: deterministic parameter validation for traversal, sensitive resources, shell controls, URL schemes/allowlists/private and special destinations, deep encodings, payload size, and malformed values; advisory task consistency; bounded risk factors and thresholds; hard-signal floors; and Gateway decision precedence.

## Missing Features

- Repository and Git baseline
- Database-backed Python environment configuration
- Full versioned contract set and security-kernel schemas
- Live PostgreSQL integration verification and health dependency checks
- Policy, approval, breaker, incident, replay, and advanced behavioral validation modules
- PostgreSQL roles/triggers and production deployment hardening
- Valkey publication worker and SSE backend
- Scripted agents and orchestrator
- LLM Client isolation for Groq, Ollama, and replay
- Docker executor and seccomp profile
- Attack Lab fixtures
- Backend unit, integration, property, security, concurrency, and full architectural tests
- CI, Compose, linting, type checking, and security scanning

## Broken Features

The Phase 2 persistence foundation is runnable against SQLite tests and configured for PostgreSQL, but live PostgreSQL/Valkey startup was not executed because Docker was unavailable. The current synchronous Gateway still hydrates in-memory registries; repository-backed registry reads are deferred. Publication workers, advanced validation, and later containment controls remain deferred.

## Security Violations

The following are currently unimplemented controls, not observed runtime bypasses:

- PostgreSQL integration was not live-validated in this environment.
- PostgreSQL role/grant hardening and deployment-specific worker configuration remain to be validated against the live database.
- No advanced parameter validation exists yet.
- No approval pause, idempotency, quarantine, or circuit breaker exists.
- No evidence yet proves that agents cannot access credentials, filesystem, databases, HTTP, Docker, or tools directly.

## Test Coverage

Thirty-four tests pass across Phase 1, Phase 2, and Phase 3, including identity, token claims, lifecycle state, capability metadata, exact tool resolution, schema validation, API execution, repositories, idempotency, outbox durability, exact audit hashing, tamper detection, concurrent appends, Valkey replay behavior, traversal/URL/shell defenses, task consistency, risk thresholds, hard-signal reasons, architecture guards, forged-receipt rejection, and no-execution-after-block. Ruff and mypy are configured but unavailable in the current environment.

## P0 Status

**Phase 3 validation/risk foundation complete.** The deterministic Gateway, persistence/audit foundation, parameter validation, task consistency, and risk/decision layer are implemented. Phase 4+ orchestration and containment are intentionally deferred.

## P1 Status

**Not started.** P1 remains deferred until P0 is stable.

## P2 Status

**Not started.** P2 remains out of scope for the initial backend implementation.

## Recommended Next Phase

Next implementation phase:

1. Implement scripted Planner, Researcher, Coder, and Executor agents through Gateway-only interfaces.
2. Add deterministic trace/replay fixtures without an LLM dependency.
3. Preserve the Phase 1-3 security tests as fast regression gates and validate persistence against live PostgreSQL when Docker is available.

No agent-facing code should bypass the Gateway. Phase 2 must not add persistence shortcuts or move decisions out of the deterministic Gateway.
