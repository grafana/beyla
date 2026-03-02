# OCI Runtime Injection (Host-Level)

This package defines a host-level auto-instrumentation path for plain Docker/container runtimes without Kubernetes admission webhooks.

## Goal

Provide zero-code SDK injection by mutating OCI specs before container start, using a runtime wrapper model.

## Why This Exists

The Kubernetes webhook in `pkg/webhook` mutates Pod specs before scheduling. For plain Docker host deployments, there is no Pod admission phase, so injection must happen at a lower level.

## Proposed Approach

Use a custom OCI runtime wrapper (`beyla-oci-runtime`) that:

1. Receives OCI runtime CLI calls from Docker/containerd.
2. Locates the OCI bundle (`config.json`).
3. Evaluates a selection policy.
4. Mutates the OCI spec (mounts + env vars).
5. Delegates execution to the real runtime (typically `runc`).

## Current Status

Architecture and core wrapper skeleton are implemented.

- Detailed architecture: `ARCHITECTURE.md`
- Docker host integration: `DOCKER.md`
- Host installation and upgrades: `OPERATIONS.md`
- Local end-to-end recipe: `E2E.md`
- Docker Compose demo: `example/docker-compose.yml`
- Ongoing context for AI handover: `AGENTS.md`

## Non-goals (Phase 1)

- Support for managed runtimes without host control.
- Full parity with Kubernetes metadata enrichment.
- Automatic restart orchestration like Kubernetes Deployment bounce.

## Language

All code and docs in this directory are maintained in English.
