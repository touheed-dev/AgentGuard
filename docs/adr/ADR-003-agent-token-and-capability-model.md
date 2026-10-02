# ADR-003: Agent Token and Capability Model

## Status

Accepted; implemented.

## Decision

Use short-lived Ed25519-signed tokens containing issuer, subject, audience, task binding, capability version, narrowed scope, security epoch, timestamps, and JTI. PostgreSQL registry state remains authoritative for capability and status checks.

## Consequences and Testing

Suspension or quarantine increments the security epoch and invalidates prior tokens without an unbounded revocation list. Test signature, issuer, audience, expiry, task, status, capability version, epoch, scope narrowing, and request replay.
