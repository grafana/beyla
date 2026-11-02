#!/usr/bin/env python3
"""Collect a bounded CI-failure report for the fix-obi triage step.

The triage model used to discover failures itself (workflow YAML, full logs,
artifacts, OBI test diffs). That blew past claude-code-action's turn check:
the action compares transcript turns, including every tool result, with
--max-turns. This script does the collection. The model only rewrites the
result into triage.md.

Agent and supervisor runs are omitted. Their failures are this workflow, not
the CI break the agent is supposed to fix, and including them makes each
retry look at a larger and larger set of runs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from typing import Iterable, Mapping, Sequence

EXCLUDED_WORKFLOWS = {
    "Fix OBI submodule CI",
    "CI Supervisor: Rerun flaky failures",
}

# Check and job names owned by the agent / supervisor. A failing shard can
# share a workflow with these; they are not product failures.
EXCLUDED_JOBS = {
    "Fix OBI submodule CI",
    "CI Supervisor: Rerun flaky failures",
    "Wait for CI completion",
    "Triage CI failures",
    "Plan fixes",
    "Implement and push",
    "Remove agent label",
    "Evaluate failed checks",
    "Add agent/fix-obi label",
    "Add agent/fix-obi-pending label",
    "Handle CI completion",
    "Request Copilot review",
}

FAILED_CONCLUSIONS = {"failure", "timed_out"}
# skipped is not green: a path-filter or label event can skip a newer run
# and leave the real failure on an older run of the same commit.
GREEN_CONCLUSIONS = {"success", "neutral"}

MAX_LOG_JOBS = 8
MAX_KEPT_LINES = 50
MAX_LINE_CHARS = 500
PRECEDING_CONTEXT = 8
FOLLOWING_CONTEXT = 4
LOG_TIMEOUT_SECONDS = 120

TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s*")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\^\[\[[0-9;]*[A-Za-z]")
INTERESTING = re.compile(
    r"(?i)(\berror\b|\bpanic:|\bfatal\b|\bexception\b|\boomkilled\b|"
    r"\bcrashloopbackoff\b|\btimed out\b|exit code|exit status|"
    r"--- FAIL:|^FAIL\b|##\[error\]|\[FAIL\]|\[FAILED\])"
)
NOISE = (
    "Node.js 20 is deprecated",
    "ubuntu-latest label will migrate",
)
# Setup scripts echo these strings. They match INTERESTING but are not failures.
BOILERPLATE = (
    "OIDC Token Error",
    "Failed to get OIDC token",
    "core.setFailed",
    "core.error(",
    "Solution 1 - Add workflow-level permissions",
)
# How far above the final failure to keep earlier hits from the same failure.
CLUSTER_GAP = 40


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="ci-context.md")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run unit tests and exit",
    )
    return parser.parse_args(argv)


def parse_concatenated_json(text: str) -> list:
    """Decode one or more JSON values concatenated the way `gh api --paginate` emits them."""
    decoder = json.JSONDecoder()
    index = 0
    values = []
    length = len(text)
    while index < length:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        value, index = decoder.raw_decode(text, index)
        values.append(value)
    return values


def choose_failed_runs(runs: Iterable[Mapping]) -> list[dict]:
    """Latest completed failure per workflow.

    A newer success or neutral run means that workflow is done and green.
    Cancelled and skipped runs are walked past so they do not hide the failure
    underneath. A newer in-progress run suppresses an older failure; triage
    starts only after CI has gone idle, and a stale excerpt would be wrong.
    """
    grouped: dict[str, list] = defaultdict(list)
    for run in runs:
        name = run.get("name") or ""
        if not name or name in EXCLUDED_WORKFLOWS:
            continue
        grouped[name].append(run)

    chosen = []
    for name, group in grouped.items():
        group.sort(key=lambda run: int(run.get("id") or 0), reverse=True)
        for run in group:
            status = run.get("status")
            if status and status != "completed":
                # A newer attempt is still running. The older failure is stale.
                break
            conclusion = run.get("conclusion")
            if conclusion in GREEN_CONCLUSIONS:
                break
            if conclusion in FAILED_CONCLUSIONS:
                chosen.append(dict(run))
                break
    chosen.sort(key=lambda run: run.get("name") or "")
    return chosen


def clean_log_message(message: str) -> str:
    text = message.replace("\ufeff", "").strip()
    text = TIMESTAMP.sub("", text)
    text = ANSI.sub("", text).strip()
    if len(text) > MAX_LINE_CHARS:
        text = text[: MAX_LINE_CHARS - 3] + "..."
    return text


def is_noise(text: str) -> bool:
    return any(snippet in text for snippet in NOISE)


def is_failure_line(text: str) -> bool:
    if any(snippet in text for snippet in BOILERPLATE):
        return False
    return INTERESTING.search(text) is not None


def excerpt_messages(messages: Iterable[str]) -> list[str]:
    """Keep the last failure cluster, not the first keyword match.

    Job logs print setup scripts (which contain the word "error") long before
    the failing test, and post-job cleanup after it. The useful lines sit just
    above the final FAIL / ##[error] marker.
    """
    cleaned = []
    for raw in messages:
        text = clean_log_message(raw)
        if text and not is_noise(text):
            cleaned.append(text)
    if not cleaned:
        return []

    hits = [index for index, text in enumerate(cleaned) if is_failure_line(text)]
    if not hits:
        return cleaned[-20:]

    anchor = hits[-1]
    cluster_start = anchor
    for index in reversed(hits):
        if anchor - index > CLUSTER_GAP:
            break
        cluster_start = index
    start = max(0, cluster_start - PRECEDING_CONTEXT)
    end = min(len(cleaned), anchor + FOLLOWING_CONTEXT + 1)
    excerpt = cleaned[start:end]
    if len(excerpt) > MAX_KEPT_LINES:
        excerpt = excerpt[-MAX_KEPT_LINES:]
    return excerpt


def failed_jobs(jobs: Iterable[Mapping]) -> list[dict]:
    selected = []
    for job in jobs:
        name = job.get("name") or ""
        if name in EXCLUDED_JOBS:
            continue
        if job.get("conclusion") not in FAILED_CONCLUSIONS:
            continue
        steps = job.get("steps") or []
        failed_steps = [
            step.get("name")
            for step in steps
            if step.get("conclusion") in FAILED_CONCLUSIONS and step.get("name")
        ]
        selected.append(
            {
                "name": name,
                "conclusion": job.get("conclusion"),
                "database_id": job.get("databaseId") or job.get("database_id"),
                "failed_steps": failed_steps,
            }
        )
    selected.sort(key=lambda job: job["name"])
    return selected


def render_context(
    *,
    pr_number: str,
    head_sha: str,
    old_obi: str | None,
    new_obi: str | None,
    runs: Sequence[Mapping],
) -> str:
    lines = [
        "# CI failure context",
        "",
        f"PR: #{pr_number}",
        f"Head SHA: {head_sha}",
        "",
        "This file is the full input for triage. Do not fetch more CI data.",
        "Agent workflow runs (Fix OBI submodule CI) and the CI supervisor are omitted.",
        "Log excerpts are capped. Artifact names are listed; artifact bodies are not downloaded.",
        "",
        "## OBI SHAs",
    ]
    if old_obi or new_obi:
        lines.append(f"- old (main): {old_obi or 'unknown'}")
        lines.append(f"- new (this branch): {new_obi or 'unknown'}")
    else:
        lines.append("- .obi-src did not resolve to a gitlink on main and on this branch.")
    lines.append("")

    if not runs:
        lines.append("No failed or timed-out pull_request workflows.")
        lines.append("")
        return "\n".join(lines)

    for run in runs:
        workflow = run.get("workflow") or "unknown workflow"
        lines.append(f"## Workflow: {workflow}")
        lines.append(f"- Run: {run.get('url') or 'unknown'}")
        lines.append(f"- Attempt: {run.get('attempt') or 'unknown'}")
        lines.append(f"- Conclusion: {run.get('conclusion') or 'unknown'}")
        artifacts = run.get("artifacts") or []
        if artifacts:
            lines.append("- Artifacts: " + ", ".join(artifacts))
        else:
            lines.append("- Artifacts: none produced")
        jobs = list(run.get("jobs") or [])
        omitted = list(run.get("omitted_jobs") or [])
        if not jobs and not omitted:
            lines.append("- No failed jobs were listed for this run.")
        for job in jobs:
            step = ", ".join(job.get("failed_steps") or []) or "unknown"
            lines.append("")
            lines.append(f"### {workflow} — {job.get('name')}")
            lines.append(f"**Status**: {job.get('conclusion')}")
            lines.append(f"**Failed step**: {step}")
            job_artifacts = artifacts_for_job(job.get("name") or "", list(artifacts))
            if job_artifacts:
                artifact_text = ", ".join(job_artifacts)
            elif artifacts:
                artifact_text = "none matched this job; see the workflow artifact list"
            else:
                artifact_text = "none produced"
            lines.append(f"**Artifacts inspected**: {artifact_text}")
            excerpt = job.get("excerpt") or []
            lines.append("**Errors**:")
            if excerpt:
                lines.extend(excerpt)
            else:
                lines.append("(no log excerpt captured)")
        if omitted:
            lines.append("")
            lines.append(
                "Additional failed jobs with no log excerpt "
                f"(at most {MAX_LOG_JOBS} excerpts across all workflows):"
            )
            for name in omitted:
                lines.append(f"- {name}")
        lines.append("")
    return "\n".join(lines)


def git_output(args: Sequence[str]) -> str | None:
    proc = subprocess.run(args, check=False, text=True, capture_output=True)
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def obi_shas(head_sha: str, base_ref: str = "origin/main") -> tuple[str | None, str | None]:
    # Prefer the PR head recorded by the API. Fall back to HEAD for a checkout
    # that has not fetched that object yet.
    new_obi = git_output(["git", "rev-parse", f"{head_sha}:.obi-src"]) or git_output(
        ["git", "rev-parse", "HEAD:.obi-src"]
    )
    return git_output(["git", "rev-parse", f"{base_ref}:.obi-src"]), new_obi


def gh_text(args: Sequence[str], *, timeout: int | None = None) -> str:
    proc = subprocess.run(
        args,
        check=True,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return proc.stdout


def gh_json(args: Sequence[str], *, timeout: int | None = None):
    return json.loads(gh_text(args, timeout=timeout))


def list_pr_runs(repo: str, head_sha: str) -> list[dict]:
    raw = gh_text(
        [
            "gh",
            "api",
            "--paginate",
            "-H",
            "Accept: application/vnd.github+json",
            f"repos/{repo}/actions/runs?head_sha={head_sha}&event=pull_request&per_page=100",
        ]
    )
    runs: list[dict] = []
    for page in parse_concatenated_json(raw):
        runs.extend(page.get("workflow_runs") or [])
    return runs


def artifact_names(repo: str, run_id: int) -> list[str]:
    try:
        payload = gh_json(
            [
                "gh",
                "api",
                f"repos/{repo}/actions/runs/{run_id}/artifacts",
                "--jq",
                "[.artifacts[].name]",
            ]
        )
    except (subprocess.CalledProcessError, json.JSONDecodeError, subprocess.TimeoutExpired):
        return []
    if not isinstance(payload, list):
        return []
    seen: set[str] = set()
    names = []
    for name in payload:
        if not name:
            continue
        text = str(name)
        if text in seen:
            continue
        seen.add(text)
        names.append(text)
    return names


def artifacts_for_job(job_name: str, artifacts: Sequence[str]) -> list[str]:
    """Artifacts whose name contains this job's shard or leaf name, as a path segment."""
    keys: list[str] = []
    shard = re.search(r"shard-(\d+)", job_name)
    if shard:
        keys.append(f"-{shard.group(1)}-")
    else:
        leaf = job_name.split()[0] if job_name else ""
        if leaf and leaf not in {"Run", "Test"}:
            keys.append(f"-{leaf}-")
    if not keys:
        return []
    matched = []
    for name in artifacts:
        haystack = f"-{name}-"
        if any(key in haystack for key in keys):
            matched.append(name)
    return matched


def job_log_messages(repo: str, run_id: int, job_id: int) -> list[str]:
    proc = subprocess.Popen(
        [
            "gh",
            "run",
            "view",
            str(run_id),
            "--repo",
            repo,
            "--job",
            str(job_id),
            "--log",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        stdout, _ = proc.communicate(timeout=LOG_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
    messages = []
    for line in (stdout or "").splitlines():
        messages.append(line.split("\t", 2)[-1])
    return messages


def collect(repo: str, pr_number: str) -> str:
    if not pr_number.isdigit():
        raise SystemExit(f"PR_NUMBER must be digits, got {pr_number!r}")
    pr = gh_json(
        [
            "gh",
            "pr",
            "view",
            pr_number,
            "--repo",
            repo,
            "--json",
            "headRefOid",
        ]
    )
    head_sha = pr["headRefOid"]
    failed = choose_failed_runs(list_pr_runs(repo, head_sha))
    rendered_runs = []
    log_budget = MAX_LOG_JOBS
    for run in failed:
        run_id = int(run["id"])
        detail = gh_json(
            [
                "gh",
                "run",
                "view",
                str(run_id),
                "--repo",
                repo,
                "--json",
                "jobs,conclusion,url,attempt,workflowName",
            ]
        )
        jobs = failed_jobs(detail.get("jobs") or [])
        with_logs = jobs[:log_budget]
        log_budget -= len(with_logs)
        omitted = [job["name"] for job in jobs[len(with_logs) :]]
        for job in with_logs:
            job_id = job.get("database_id")
            excerpt: list[str] = []
            if job_id:
                try:
                    excerpt = excerpt_messages(job_log_messages(repo, run_id, int(job_id)))
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    excerpt = [f"(log fetch failed: {exc})"]
            job["excerpt"] = excerpt
        rendered_runs.append(
            {
                "workflow": detail.get("workflowName") or run.get("name"),
                "url": detail.get("url"),
                "attempt": detail.get("attempt"),
                "conclusion": detail.get("conclusion") or run.get("conclusion"),
                "artifacts": artifact_names(repo, run_id),
                "jobs": with_logs,
                "omitted_jobs": omitted,
            }
        )
    old_obi, new_obi = obi_shas(head_sha)
    return render_context(
        pr_number=pr_number,
        head_sha=head_sha,
        old_obi=old_obi,
        new_obi=new_obi,
        runs=rendered_runs,
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.self_test:
        raise SystemExit("self-test is handled by __main__")
    repo = os.environ.get("REPO") or ""
    pr_number = os.environ.get("PR_NUMBER") or ""
    if not repo or not pr_number:
        raise SystemExit("REPO and PR_NUMBER are required")
    text = collect(repo, pr_number)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(
        f"Wrote {args.output} ({len(text)} bytes, "
        f"{text.count('### ')} job section(s))"
    )


# --- tests ---


def _test_choose_failed_runs_skips_agent_and_superseded_failures() -> None:
    runs = [
        {"id": 1, "name": "Fix OBI submodule CI", "status": "completed", "conclusion": "failure"},
        {"id": 2, "name": "CI Supervisor: Rerun flaky failures", "status": "completed", "conclusion": "success"},
        {"id": 3, "name": "Pull request checks", "status": "completed", "conclusion": "failure"},
        {"id": 4, "name": "Pull request checks", "status": "completed", "conclusion": "success"},
        {"id": 5, "name": "PR OATS test", "status": "completed", "conclusion": "failure"},
        {"id": 6, "name": "PR OATS test", "status": "completed", "conclusion": "cancelled"},
        {"id": 7, "name": "Helm Test", "status": "completed", "conclusion": "failure"},
        {"id": 8, "name": "Helm Test", "status": "in_progress", "conclusion": None},
        {"id": 10, "name": "Documentation CI", "status": "completed", "conclusion": "failure"},
        {"id": 11, "name": "Documentation CI", "status": "completed", "conclusion": "skipped"},
    ]
    chosen = choose_failed_runs(runs)
    # OATS walks back past the cancelled rerun. Helm's newer in-progress run wins.
    # Pull request checks' newer success hides the older failure.
    # Documentation CI walks back past the newer skipped run.
    assert [run["id"] for run in chosen] == [10, 5], chosen


def _test_excerpt_keeps_failure_context_not_preamble() -> None:
    messages = [
        "core.setFailed(`❌ Failed to get OIDC token: ${error.message}`)",
        "🔧 OIDC Token Error - How to Fix:",
        "Current runner version: '2.338.2'",
        "Node.js 20 is deprecated. The following actions target Node.js 20",
        *([f"setup step {index} ok" for index in range(12)]),
        "go test ./internal/foo",
        "=== RUN   TestParse",
        "    parse_test.go:12: expected 1, got 2",
        "--- FAIL: TestParse (0.01s)",
        "FAIL",
        "FAIL\tgithub.com/grafana/beyla/internal/foo\t0.02s",
    ]
    excerpt = excerpt_messages(messages)
    assert any("--- FAIL: TestParse" in line for line in excerpt), excerpt
    assert any("expected 1, got 2" in line for line in excerpt), excerpt
    assert not any("runner version" in line for line in excerpt), excerpt
    assert not any("Node.js 20" in line for line in excerpt), excerpt
    assert not any("OIDC" in line for line in excerpt), excerpt


def _test_failed_jobs_ignore_agent_jobs_and_record_steps() -> None:
    jobs = failed_jobs(
        [
            {
                "name": "Triage CI failures",
                "conclusion": "failure",
                "databaseId": 1,
                "steps": [{"name": "Run Claude Code – Triage", "conclusion": "failure"}],
            },
            {
                "name": "shard-0 (5 tests)",
                "conclusion": "failure",
                "databaseId": 9,
                "steps": [
                    {"name": "Checkout", "conclusion": "success"},
                    {"name": "Run integration tests", "conclusion": "failure"},
                ],
            },
            {"name": "Lint", "conclusion": "success", "databaseId": 3, "steps": []},
        ]
    )
    assert len(jobs) == 1
    assert jobs[0]["name"] == "shard-0 (5 tests)"
    assert jobs[0]["failed_steps"] == ["Run integration tests"]
    assert jobs[0]["database_id"] == 9


def _test_render_lists_omitted_jobs_and_shas() -> None:
    text = render_context(
        pr_number="3211",
        head_sha="abc",
        old_obi="111",
        new_obi="222",
        runs=[
            {
                "workflow": "Pull request integration tests",
                "url": "https://example.test/run/1",
                "attempt": 2,
                "conclusion": "failure",
                "artifacts": ["logs"],
                "jobs": [
                    {
                        "name": "shard-0 (5 tests)",
                        "conclusion": "failure",
                        "failed_steps": ["Run integration tests"],
                        "excerpt": ["--- FAIL: TestFoo"],
                    }
                ],
                "omitted_jobs": ["shard-9 (9 tests)"],
            }
        ],
    )
    assert "- old (main): 111" in text
    assert "- new (this branch): 222" in text
    assert "### Pull request integration tests — shard-0 (5 tests)" in text
    assert "--- FAIL: TestFoo" in text
    assert "shard-9 (9 tests)" in text
    assert "Fix OBI submodule CI" not in text.split("## Workflow:", 1)[-1]


def _test_artifacts_for_job_does_not_confuse_shard_prefixes() -> None:
    artifacts = [
        "go-integration-test-logs-0-9055",
        "go-integration-test-logs-10-9055",
        "oats-test-logs-ai-8372",
    ]
    assert artifacts_for_job("shard-0 (5 tests)", artifacts) == [
        "go-integration-test-logs-0-9055"
    ]
    assert artifacts_for_job("shard-10 (9 tests)", artifacts) == [
        "go-integration-test-logs-10-9055"
    ]
    assert artifacts_for_job("ai", artifacts) == ["oats-test-logs-ai-8372"]


def _test_paginated_json() -> None:
    raw = '{"workflow_runs":[{"id":1}]}\n{"workflow_runs":[{"id":2}]}'
    pages = parse_concatenated_json(raw)
    assert [page["workflow_runs"][0]["id"] for page in pages] == [1, 2]


def _run_self_tests() -> None:
    tests = [
        _test_choose_failed_runs_skips_agent_and_superseded_failures,
        _test_excerpt_keeps_failure_context_not_preamble,
        _test_failed_jobs_ignore_agent_jobs_and_record_steps,
        _test_render_lists_omitted_jobs_and_shas,
        _test_artifacts_for_job_does_not_confuse_shard_prefixes,
        _test_paginated_json,
    ]
    for test in tests:
        test()
        print(f"ok {test.__name__}")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        _run_self_tests()
    else:
        main()
