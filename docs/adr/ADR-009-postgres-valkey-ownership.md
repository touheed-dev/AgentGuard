# ADR-009: PostgreSQL and Valkey Ownership

## Status

Accepted; implemented.

## Decision

PostgreSQL is authoritative for agents, tools, policies, tasks, approvals, incidents, traces, executions, audit events, breaker state, and outbox records. Valkey is limited to live event delivery, short-lived counters, and ephemeral coordination.

## Security and Testing

Valkey outages cannot erase security state. Counters are recomputed from PostgreSQL and critical tools fail closed when required. Test outage behavior, outbox recovery, duplicate delivery, and sole-source violations.
