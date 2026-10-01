# ADR-005: Policy Precedence and Conflict Resolution

## Status

Accepted by PRD v2.4.1; implementation pending.

## Decision

Evaluate policies by critical deny, identity/capability, resource/parameter, communication, task consistency, approval, warning, and default deny precedence. Among hard outcomes, `BLOCK > REQUIRE_APPROVAL > WARN > ALLOW`; advisory rules cannot independently block.

## Security and Testing

Use bounded CEL context only. Add conflict tests proving hard denials cannot be softened by risk or advisory outcomes.
