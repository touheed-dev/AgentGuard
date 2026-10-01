# AgentGuard Backend Implementation Status

**Baseline:** 2026-10-02  
**Source of truth:** `AgentGuard — PRD v2.4.1 (Architecture Lock).md`  
**Scope:** Backend and security/control plane only

## Audit Summary

The initial audit found only the authoritative PRD. Phase 0 and the Phase 1 deterministic Gateway spine now exist; persistence and later control-plane modules remain deferred.

The repository is now at the end of Phase 1 and is ready for a Phase 2 persistence checkpoint.

## Current Architecture

The implemented slice is a Python 3.12+ modular monolith with a FastAPI Gateway, in-process Ed25519 identity, in-memory agent/tool registries, deterministic capability and schema checks, and a receipt-checked stub executor. PostgreSQL, Valkey, and the Docker executor remain future boundaries.

## Implemented Features

Phase 0 foundation: shared Pydantic contracts, FastAPI health endpoint, replay-mode Compose services, OpenAPI export, seven JSON Schema exports, and test tooling.

Phase 1: Ed25519 token issuance/verification, agent registry, lifecycle/security-state checks, capability enforcement including declared tool capabilities, exact tool registry, basic object-schema validation, deterministic `Gateway.authorize()`, evaluate/execute endpoints, and a stub executor that accepts only one-time Gateway-issued ALLOW/WARN grants.

## Missing Features

- Repository and Git baseline
- Database-backed Python environment configuration
- Full versioned contract set and security-kernel schemas
- PostgreSQL-backed authorization state and health dependency checks
- Policy, risk, approval, breaker, audit, incident, replay, and advanced validation modules
- SQLAlchemy models, Alembic migrations, PostgreSQL roles, and transactional outbox
- Valkey event delivery and SSE backend
- Scripted agents and orchestrator
- LLM Client isolation for Groq, Ollama, and replay
- Docker executor and seccomp profile
- Attack Lab fixtures
- Backend unit, integration, property, security, concurrency, and full architectural tests
- CI, Compose, linting, type checking, and security scanning

## Broken Features

The Phase 1 Gateway is runnable, but persistence, duplicate-request handling, advanced parameter validation, and later containment controls are not implemented yet.

## Security Violations

The following are currently unimplemented controls, not observed runtime bypasses:

- No PostgreSQL-backed Gateway state exists yet.
- No request replay/idempotency persistence exists yet.
- No advanced parameter validation exists yet.
- No approval pause, idempotency, quarantine, or circuit breaker exists.
- No append-only audit chain exists.
- No evidence yet proves that agents cannot access credentials, filesystem, databases, HTTP, Docker, or tools directly.

## Test Coverage

Twenty-two Phase 1 tests pass, including identity, token claims, lifecycle state, capability metadata, exact tool resolution, schema validation, API execution, architecture guards, forged-receipt rejection, grant substitution rejection, and no-execution-after-block. Ruff and mypy are configured but unavailable in the current environment.

## P0 Status

**Phase 1 complete.** The deterministic Gateway spine is implemented and tested. Persistence and later security modules are intentionally deferred.

## P1 Status

**Not started.** P1 remains deferred until P0 is stable.

## P2 Status

**Not started.** P2 remains out of scope for the initial backend implementation.

## Recommended Next Phase

Next implementation phase:

1. Add PostgreSQL models and migrations without changing the Gateway decision contract.
2. Add the transactional outbox and Valkey delivery boundary.
3. Preserve the Phase 1 in-memory tests as fast security-kernel tests.

No agent-facing code should bypass the Gateway. Phase 2 must not add persistence shortcuts or move decisions out of the deterministic Gateway.
