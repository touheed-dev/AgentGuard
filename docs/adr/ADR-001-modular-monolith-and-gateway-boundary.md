# ADR-001: Modular Monolith and Gateway Boundary

## Status

Accepted; implemented.

## Decision

Use a modular monolith with one FastAPI Gateway process hosting typed security modules. Every tool, resource, execution, and agent message enters through the Gateway. Tool implementations are reachable only through the Gateway executor interface.

## Alternatives and Consequences

Distributed security services, direct agent-to-tool calls, and frontend authorization were rejected because they increase bypass surface or move trust into untrusted components. In-process calls simplify deterministic ordering and replay, so import boundaries and architectural tests are required.

## Security and Testing

Test authorization-before-execution and fail CI on direct tool, HTTP, filesystem, database, Docker, or network access from agents and orchestrators.
