# ADR-004: Groq Model Selection

## Status

Proposed; model intentionally unselected.

## Decision

Keep `GROQ_MODEL` configurable. Select and pin a model based on benchmarks covering structured output, correct proposals, latency, injection reproducibility, rate-limit tolerance, and context handling.

## Security and Testing

The model may propose actions only; the Gateway remains authoritative. Benchmark artifacts contain synthetic data only and no credentials. Replay remains the canonical path.
