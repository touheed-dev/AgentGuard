# ADR-007: Executor Sandbox Security Profile

## Status

Accepted; implemented.

## Decision

Run code in a separate Docker container with read-only root, disabled network, non-root user `10001:10001`, all capabilities dropped, no-new-privileges, seccomp, process/memory/CPU limits, noexec temporary storage, isolated workspace, hard timeout, and no Docker socket.

## Consequences and Testing

This is constrained P0 demonstration isolation, not escape-proof isolation. Inspect container configuration and test that no socket, network, host filesystem, or credential is exposed.
