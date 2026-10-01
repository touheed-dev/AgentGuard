# ADR-008: Audit-Chain Canonicalization and Checkpoints

## Status

Accepted by PRD v2.4.1; implementation pending.

## Decision

Hash each event as `SHA256(bytes.fromhex(previous_hash) + b"." + JCS(event_without_hash_fields))` using UTF-8 RFC 8785 canonical JSON and a 32-byte zero genesis hash. Use a dedicated writer, advisory lock, unique sequence constraint, append-only triggers, and a restricted application role.

## Security and Testing

Test concurrent writers, restart verification, modified events, truncated chains, and rejected updates/deletes. Signed external checkpoints remain P1.
