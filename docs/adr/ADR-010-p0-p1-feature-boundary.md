# ADR-010: P0/P1 Feature Boundary

## Status

Accepted; implemented.

## Decision

Finish and stabilize the P0 kernel and required demonstration path before implementing P1 differentiators. P0 includes the Gateway, deterministic controls, audit, replay, approval, containment, four agents, Attack Lab, executor, and the six dashboard-facing backend surfaces.

## Consequences and Testing

Advanced analytics, Reviewer, Agent Twin, policy mutation, signed checkpoints, and stronger isolation remain deferred and cannot destabilize P0. P0 gates include post-block execution rate zero, replay determinism, architectural invariants, audit verification, and approval freshness.
