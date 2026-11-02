# Write triage.md from collected CI context

**Triggering PR**: #{{PR_NUMBER}} — "{{PR_TITLE}}"

`ci-context.md` in the repo root is a complete extract of the CI failures and the OBI submodule SHAs. Collection already happened. Your only job is to rewrite that file into `triage.md`.

## Rules

- Read `ci-context.md`. Write `triage.md`. Stop.
- Do not run shell commands, list workflow runs, read logs, read source, inspect artifacts, or spawn subagents. Do not open any other file.
- Do not analyse root causes, suggest fixes, or edit any file other than `triage.md`.
- Copy facts across. Keep every failing job that `ci-context.md` lists. Preserve error lines verbatim.
- If a field is missing, write `unknown`. Do not go looking for it.
- Jobs that `ci-context.md` names but did not excerpt must still appear, with the errors line `(log excerpt omitted; see the additional-jobs list in ci-context.md)`.

## `triage.md` structure

```
# CI failure triage

## OBI SHAs
- old (main): <sha or unknown>
- new (this branch): <sha or unknown>

## <Workflow Name> — <Job Name>
**Status**: failed | timed_out
**Failed step**: <step name or unknown>
**Artifacts inspected**: <list or "none produced">
**Errors**:
<error lines, copied verbatim>
```

If `ci-context.md` says there are no failed workflows, write the OBI SHAs section and one line: `No failed or timed-out CI workflows.`
