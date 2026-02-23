---
# Fix OBI submodule CI — run when the automated OBI update PR fails CI.
# Trigger: add the "agent/fix-obi" label to a PR (e.g. the "Update OBI submodule to <sha>" PR).
description: "Analyze OBI submodule update PR CI failures and suggest or apply fixes"
on:
  pull_request:
    types: [labeled]
    names: [agent/fix-obi]
permissions:
  contents: read
  pull-requests: read
  issues: read
  id-token: write
steps:
  - name: Get vault secrets
    id: vault-secrets
    uses: grafana/shared-workflows/actions/get-vault-secrets@f1614b210386ac420af6807a997ac7f6d96e477a # get-vault-secrets/v1.3.1
    with:
      # Vault path: ci/repo/grafana/beyla/github-actions
      repo_secrets: |
        ANTHROPIC_API_KEY=anthropic-token:token
  - name: Init .obi-src submodule
    run: git submodule update --init --recursive .obi-src
engine: claude
tools:
  bash: ["gh", "make", "go", "git"]
  github:
    toolsets: [pull_requests, issues]
    read-only: true
  edit: {}
safe-outputs:
  add-comment:
    max: 5
timeout-minutes: 15
---

# Fix OBI submodule CI

This workflow runs when the **agent/fix-obi** label is added to a pull request (for example, on the automated "Update OBI submodule to \<sha\>" PR when it fails CI due to breaking changes from upstream OBI).

## Context

- **Triggering PR**: "${{ needs.activation.outputs.text }}"
- **Repository**: This repo (beyla). The OBI submodule is in `.obi-src` and is updated by the "Update OBI submodule" workflow (`bot_sync-obi-submodule.yml`), which can fail when upstream introduces breaking changes.
- **Submodule checkout**: The workflow checks out the repo **without** the `.obi-src` submodule by default (the compiled job uses a plain `actions/checkout` with no `submodules` option). A step runs `git submodule update --init --recursive .obi-src` before the agent; if the PR branch was checked out after that step, run **`git submodule update --init --recursive`** (or **`git submodule update --init .obi-src`**) yourself before inspecting `.obi-src` or running `make vendor-obi`.

## Beyla/OBI integration

- **Generated tests**: `scripts/generate-obi-tests.sh` runs as part of `make vendor-obi`. It copies, transforms, and merges the OBI test suites with `internal/test/beyla_extensions` into `internal/testgenerated`. **Do not modify files in `internal/testgenerated`** — they are regenerated; change the script or source extensions instead.
- **Where breaking changes usually land**: OBI introduces breaking changes regularly. These typically require:
  - **Config**: updates in `pkg/beyla/config.go` (and related OBI override logic).
  - **Go symbols**: refactoring to match OBI API/package changes.
- **Go version and obi-generator**: If the Go version has been upgraded (e.g. in OBI or in Beyla’s tooling), a **new version of the obi-generator** may be required. The image is set in the root **`Dockerfile`** via `ARG GEN_IMG` (lines 2–3). The Go version used by the obi-generator is likely defined in **`.obi-src/generator.Dockerfile`** (base image, lines 1–2). Align the obi-generator image with the Go version used for the build/tests.
- **Static check**: After making changes, run **`make fmt lint`** (or at least **`make lint`**). It must pass as a basic first static check.
- **Porting from OBI**: Other breakages visible in CI logs should be ported from OBI into Beyla (Beyla follows a similar code structure). Make changes in the context of the Beyla repo and follow Beyla-specific naming. Inspect Beyla/OBI differences documented in `scripts/generate-obi-tests.sh`: **BEHAVIORAL_TRANSFORMS** (env renames, identity, paths; around lines 63–64) and **CODE_INJECTIONS** (path setup, config overrides; around lines 120–121). Consider whether `scripts/generate-obi-tests.sh` needs updating so that it still produces idempotent output for other developers cloning Beyla with the OBI submodule, or whether OBI has drifted so that the transforms and injections need to be updated to match.
- **CI vs local**: The CI test suite runs multiple long-running workflows on Linux (ARM and x86) with BPF. You may not be able to reproduce complex failures locally. **Rely on the CI logs** rather than re-running the full test suite locally (tests are slow and often need nested virtualization via QEMU, kind clusters, etc.). If needed, run **`make fmt lint`** as a quick static check; only run a single unit test if absolutely necessary. Integration tests are unlikely to complete without an appropriate environment — rely heavily on CI logs and on the **git history of the `.obi-src` submodule** to infer what needs to be ported into Beyla.

## Your task

1. **Understand the failure**: Use the GitHub tools to read the triggering PR’s title, body, and labels, and to list recent workflow runs and failed jobs for that PR. Identify which jobs failed and why (e.g. build, tests, vendoring). Prefer CI logs over local reproduction.

2. **Inspect the codebase**: Ensure `.obi-src` is present — if it is missing or empty, run **`git submodule update --init --recursive`** (or **`git submodule update --init .obi-src`**). Then run **`make fmt lint`** as a quick static check; run a single unit test only if necessary. Do not attempt to run the full integration test suite locally.

3. **Propose a fix**: Based on the failure, suggest or implement a minimal fix. Prefer:
   - Code or config changes in this repo (outside `.obi-src`) to adapt to OBI changes — especially `pkg/beyla/config.go` and Go symbol refactoring; do not edit `internal/testgenerated` (see Beyla/OBI integration above). If the failure points to test or transform drift, consider updating `scripts/generate-obi-tests.sh`.
   - If you cannot fix without changing `.obi-src`, describe the required upstream change and add a short comment on the PR with your findings and a concrete suggestion (branch/commit to use, or a patch idea).

4. **Respond on the PR**: Use the add-comment safe output to post a concise summary on the PR:
   - What failed and why.
   - What you changed or recommend (with file/line references if applicable).
   - Next steps (e.g. “re-run CI after pushing” or “wait for upstream fix”).

Do not force-push or overwrite the submodule commit unless the instructions explicitly require it. Prefer fixes in the Beyla tree that work with the current OBI submodule commit.
