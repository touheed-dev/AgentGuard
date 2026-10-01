# ADR-002: Replay as Canonical Execution Mode

## Status

Accepted by PRD v2.4.1; implementation pending.

## Decision

Recorded proposals run through the same Gateway as live Groq, Ollama, and hand-written proposals. Replay is mandatory for CI, Attack Lab, and offline demos and uses deterministic clocks and ID generation.

## Consequences and Testing

The system remains demonstrable without network access or credentials. Identical inputs must produce identical decisions independent of provider; provider failures must never become fallback tool actions.
