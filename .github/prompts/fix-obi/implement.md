# Implement fixes from plan

**Triggering PR**: #{{PR_NUMBER}} — "{{PR_TITLE}}"

Triage and root cause analysis are already complete. Your only job is to **implement the plan and push**. Do not re-triage, re-analyse failures, download CI logs, or download artifacts.

## Inputs

- **`plan.md`** (repo root) — your implementation spec. Follow it exactly, in order.
- **`triage.md`** (repo root) — reference only if plan.md directs you to it for additional context.
- Source code as needed, including `.obi-src/` for reference when porting OBI changes.

## Forbidden directories — never modify

- **`vendor/`** — vendored OBI code; correct by definition if OBI CI passes.
- **`.obi-src/`** — the OBI submodule.
- **`internal/testgenerated/`** — generated output; change scripts or extensions instead.

## Process

1. **Read `plan.md`** and implement every item in order.
2. **Run verification** as specified in plan.md (typically `make fmt lint` or `go vet ./...`). Fix any errors before committing.
3. **Commit and push** to this PR branch using the commit signing API (no local git push). Post a concise PR comment summarising: what files were changed, what was fixed, and any recommended upstream (OBI) changes noted in the plan.

## Rules

- Do not skip or disable tests — fix the underlying cause.
- Prefer porting proper fixes from OBI into Beyla over code injections in `scripts/generate-obi-tests.sh`.
- Read-only git for inspection; use provided tools to commit and push. Do not force-push or change the submodule pointer.
