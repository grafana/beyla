# Extract CI failure context

**Triggering PR**: #{{PR_NUMBER}} — "{{PR_TITLE}}"
**Repository**: beyla. OBI submodule is in `.obi-src`.

Your job is to **extract and record** failure information for the next step. Do **not** analyse root causes, suggest fixes, or make code changes. Present facts only — describe **what** failed and **what** the error output says, never **why**.

## Steps

1. **List failed/timed-out workflow runs** for this PR using `gh run list` and `gh pr checks`. Record every failed or timed-out job.

2. **Inspect workflow definitions**: For each failing workflow, read its YAML file under `.github/workflows/` to understand:
   - Which steps run and in what order.
   - Whether the workflow uploads **artifacts** (look for `actions/upload-artifact`). Note artifact names and what they contain.

3. **Extract failure context from run logs**: For each failing job, use `gh run view --log-failed` or download logs. Logs are large — use **grep**, **tail**, **head** to extract:
   - Error messages, stack traces, panics.
   - Timeout messages or hung-step indicators.
   - Container crash indicators (CrashLoopBackOff, restart counts, OOMKilled).
   - The specific step name that failed and its exit code.
   - Do **not** load entire log files into context.

4. **Download and inspect artifacts**: If failing workflows upload artifacts and the artifacts exist for the failed run, download them with `gh run download` and grep/head/tail for errors, panics, failures, and timeouts. Artifacts often contain additional logs not visible in the run output.

5. **Record OBI submodule SHAs**: This PR likely moves the OBI submodule forward. Record the **old SHA** (on `main`) and **new SHA** (on this branch) using `git diff main -- .obi-src`. These SHAs are critical — the next step uses them to identify which OBI changes introduced breaking changes.

6. **Write `triage.md`** in the repo root with this structure per failing workflow:

   ```
   ## <Workflow Name> — <Job Name>
   **Status**: failed | timed_out
   **Failed step**: <step name> (exit code <N> | timeout)
   **Artifacts inspected**: <list or "none produced" or "none available">
   **Errors**:
   <extracted error lines, stack traces, panics — with enough surrounding context>
   ```

   At the top of the file, include an **OBI SHAs** section if the submodule changed.

**Output**: Only create/update **`triage.md`**. No other file changes. No analysis. No root cause discussion.
