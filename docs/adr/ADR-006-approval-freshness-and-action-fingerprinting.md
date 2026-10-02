# ADR-006: Approval Freshness and Action Fingerprinting

## Status

Accepted; implemented.

## Decision

Fingerprint canonical action fields with RFC 8785 JCS and SHA-256 at request time. Recompute before execution and reject changed arguments, policy, resource scope, task, tool definition, or agent state as `APPROVAL_STALE`.

## Security and Testing

Protected values remain redacted in approval responses. Test tampering, policy changes, expiry, suspension, quarantine, and task cancellation.
