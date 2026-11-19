"""Pure policy helpers for the managed OBI adoption supervisor route.

This module deliberately has no GitHub client. Callers must obtain fresh PR
and check evidence from the API and pass the evidence here for validation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

from obi_adoption_repair import RepairError

MANAGED_BRANCH_RE = re.compile(r"^update-obi-adoption-([0-9a-f]{40})$")
PR_MARKER_RE = re.compile(
    r"<!-- grafana-beyla-obi-adoption:v1 target=([0-9a-f]{40}) "
    r"base=([0-9a-f]{40}) -->"
)

# These workflow paths are the adoption readiness policy, not the repository's
# branch-protection policy. Keep this list explicit and review it when workflows
# or .obi-src path filters change.
REQUIRED_WORKFLOW_PATHS = (
    ".github/workflows/pull_request.yml",
    ".github/workflows/pull_request_check_license.yml",
    ".github/workflows/pull_request_beyla_integration_tests.yml",
    ".github/workflows/pull_request_integration_tests.yml",
    ".github/workflows/pull_request_integration_tests_arm.yml",
    ".github/workflows/pull_request_k8s_integration_tests.yml",
    ".github/workflows/pull_request_oats_test.yml",
    ".github/workflows/pull_request_test_docker_build.yml",
    ".github/workflows/workflow_integration_tests_vm.yml",
)
WRITER_FLAG = "OBI_ADOPTION_WRITER_ENABLED"
REPAIR_FLAG = "OBI_ADOPTION_REPAIR_ENABLED"


def repair_gate_enabled(
    *, allow_repair: bool, environment: dict[str, str] | None = None
) -> bool:
    """Require an explicit CLI opt-in and both independent default-off repo flags."""
    env = os.environ if environment is None else environment
    return (
        allow_repair
        and env.get(WRITER_FLAG) == "true"
        and env.get(REPAIR_FLAG) == "true"
    )


def managed_target(branch: str) -> str | None:
    """Return the immutable target SHA for a well-formed managed branch."""
    match = MANAGED_BRANCH_RE.fullmatch(branch)
    return match.group(1) if match else None


def validate_pr_identity(
    *,
    branch: str,
    body: str,
    pr_number: int,
    expected_pr_number: int,
    base_ref: str,
    head_repository: str,
    repository: str,
) -> dict[str, Any]:
    """Validate API-read PR metadata against the exact managed branch marker."""
    target = managed_target(branch)
    markers = list(PR_MARKER_RE.finditer(body or ""))
    if target is None or len(markers) != 1:
        raise ValueError("PR is not a uniquely marked managed adoption PR")
    if pr_number != expected_pr_number:
        raise ValueError("workflow run and PR number do not match")
    if base_ref != "main":
        raise ValueError("managed adoption PR must target main")
    if head_repository != repository:
        raise ValueError("managed adoption PR must be from the same repository")
    marker_target, marker_base = markers[0].groups()
    if marker_target != target:
        raise ValueError("branch target and PR marker target differ")
    return {"target_sha": target, "base_sha": marker_base, "pr_number": pr_number}


def validate_inventory(inventory: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Validate the trusted workflow-path to immutable workflow-ID mapping."""
    by_path: dict[str, dict[str, Any]] = {}
    for item in inventory:
        path = item.get("path")
        workflow_id = item.get("workflow_id")
        if path not in REQUIRED_WORKFLOW_PATHS or path in by_path:
            raise ValueError("workflow inventory contains an unknown or duplicate path")
        if (
            isinstance(workflow_id, bool)
            or not isinstance(workflow_id, int)
            or workflow_id <= 0
        ):
            raise ValueError("workflow inventory has an invalid workflow ID")
        by_path[path] = item
    missing = set(REQUIRED_WORKFLOW_PATHS) - set(by_path)
    if missing:
        raise ValueError(f"workflow inventory is incomplete: {sorted(missing)}")
    return by_path


def _parse_time(value: str) -> datetime:
    if not value:
        raise ValueError("missing check deadline/observation time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamps must include a UTC offset")
    return parsed


def evaluate_required_checks(
    *,
    inventory: list[dict[str, Any]],
    runs: list[dict[str, Any]],
    pr_number: int,
    target_sha: str,
    head_sha: str,
    base_sha: str,
    merge_sha: str,
    observed_at: str,
    deadline: str,
) -> dict[str, Any]:
    """Evaluate only current, expected GitHub Actions PR runs.

    A missing or mismatched required workflow remains waiting before the
    deadline and becomes blocked/unknown at the deadline. Only a complete set
    of terminal, passing, exact-head evidence can become ready. Concrete
    failures are exposed only after the whole expected set is terminal.
    """
    expected = validate_inventory(inventory)
    now = _parse_time(observed_at)
    due = now >= _parse_time(deadline)
    selected: dict[str, dict[str, Any]] = {}
    invalid: list[str] = []

    for run in runs:
        path = run.get("workflow_path")
        if path not in expected:
            continue
        item = expected[path]
        if run.get("workflow_id") != item["workflow_id"]:
            invalid.append(path)
            continue
        if (
            run.get("app_slug") != "github-actions"
            or run.get("event") != "pull_request"
            or run.get("pr_number") != pr_number
            or run.get("pr_head_sha") != head_sha
            or run.get("base_sha") != base_sha
            or run.get("merge_sha") != merge_sha
            # The trusted core workflows use the default pull_request checkout,
            # which is the current synthetic merge commit, not the branch SHA.
            # Do not infer a tested merge from the PR association alone.
            # Actions exposes the workflow-run/check-suite head SHA (normally
            # the PR branch head), while the trusted workflow's default
            # pull_request checkout is the merge ref. Keep these distinct.
            or run.get("run_head_sha") != head_sha
        ):
            invalid.append(path)
            continue
        prior = selected.get(path)
        key = (int(run.get("run_id", 0)), int(run.get("attempt", 0)))
        prior_key = (
            (int(prior.get("run_id", 0)), int(prior.get("attempt", 0)))
            if prior
            else (-1, -1)
        )
        if key > prior_key:
            selected[path] = run

    # Stale head/base runs and `push` runs may be present for the same SHA.
    # They are not evidence, but must not poison a separate exact PR run.
    invalid = sorted(set(invalid) - set(selected))
    missing = sorted(set(REQUIRED_WORKFLOW_PATHS) - set(selected))
    incomplete = sorted(
        path
        for path, run in selected.items()
        if run.get("status") != "completed" or not run.get("conclusion")
    )
    unknown_terminal = sorted(
        path
        for path, run in selected.items()
        if run.get("status") == "completed"
        and run.get("conclusion") not in {"success", "failure", "timed_out"}
    )
    if missing or incomplete or invalid or unknown_terminal:
        return {
            "stage": "blocked" if due else "waiting",
            "reason": "required-check-evidence-unknown"
            if due
            else "required-checks-pending",
            "missing": missing,
            "incomplete": incomplete,
            "invalid": sorted(set(invalid)),
            "unknown_terminal": unknown_terminal,
            "repairable_run_ids": [],
        }

    failures = [
        (path, run)
        for path, run in selected.items()
        if run.get("conclusion") in {"failure", "timed_out"}
    ]
    if failures:
        return {
            "stage": "repairable",
            "reason": "verified-required-check-failure",
            "missing": [],
            "incomplete": [],
            "invalid": [],
            "repairable_run_ids": [run["run_id"] for _, run in failures],
        }
    return {
        "stage": "ready-for-human-review",
        "reason": "all-adoption-readiness-checks-passed",
        "missing": [],
        "incomplete": [],
        "invalid": [],
        "repairable_run_ids": [],
    }


def next_repair_budget(
    *,
    prior_state: dict[str, Any] | None,
    pr_number: int,
    target_sha: str,
    head_sha: str,
    base_sha: str,
    max_attempts: int = 2,
) -> dict[str, Any]:
    """Reserve a bounded attempt without resetting a target's prior budget.

    `prior_state` must already have been parsed from a uniquely identified
    status comment authored by the trusted bot. Missing/corrupt state for a
    previously initialized PR must be treated as an error by the caller, not
    passed as `None`.
    """
    if max_attempts != 2:
        raise ValueError("pilot repair budget is fixed at two attempts")
    used = 0
    if prior_state is not None:
        if prior_state.get("schema_version") != 1:
            raise ValueError("unsupported status-state schema")
        if prior_state.get("pr_number") != pr_number:
            raise ValueError("status state belongs to another PR")
        if prior_state.get("target_sha") != target_sha:
            raise ValueError("status state belongs to another target")
        if prior_state.get("base_sha") != base_sha:
            raise ValueError("base changed; fresh status state is required")
        budget = prior_state.get("repair_budget")
        if not isinstance(budget, dict) or budget.get("max") != max_attempts:
            raise ValueError("repair budget is missing or has changed")
        used = budget.get("used")
        if isinstance(used, bool) or not isinstance(used, int) or used < 0:
            raise ValueError("repair budget is corrupt")
        if (
            prior_state.get("stage") == "repairing"
            and isinstance(prior_state.get("reservation"), dict)
            and prior_state["reservation"].get("attempt") == used
        ):
            return {
                "allowed": False,
                "attempt": None,
                "used": used,
                "max": max_attempts,
                "reason": "repair-already-reserved",
            }
        # A new head does not reset the PR+target budget. The prior head is
        # allowed to differ; current head is bound in this reservation.
    if used >= max_attempts:
        return {"allowed": False, "attempt": None, "used": used, "max": max_attempts}
    attempt = used + 1
    return {
        "allowed": True,
        "attempt": attempt,
        "used": attempt,
        "max": max_attempts,
        "reservation": {
            "pr_number": pr_number,
            "target_sha": target_sha,
            "base_sha": base_sha,
            "head_sha": head_sha,
            "attempt": attempt,
        },
    }


def _trusted_api(token: str):
    # Imported only in the trusted default-branch CLI, never from PR code.
    from obi_adoption_repair import GitHub

    return GitHub("grafana/beyla", token)


def _status_comments(github: Any, pr_number: int) -> list[dict[str, Any]]:
    from obi_adoption_repair import STATUS_MARKER

    comments = github.request(
        "GET", f"/issues/{pr_number}/comments?per_page=100&page=1"
    )
    if not isinstance(comments, list):
        raise TypeError("Could not read PR comments")
    return [
        comment for comment in comments if STATUS_MARKER in (comment.get("body") or "")
    ]


def _author_is_trusted(comment: dict[str, Any]) -> bool:
    from obi_adoption_repair import TRUSTED_STATUS_ID, TRUSTED_STATUS_LOGIN

    user = comment.get("user") or {}
    return (
        user.get("login") == TRUSTED_STATUS_LOGIN
        and user.get("id") == TRUSTED_STATUS_ID
    )


def _workflow_inventory(github: Any) -> list[dict[str, Any]]:
    listing = github.request("GET", "/actions/workflows?per_page=100&page=1")
    workflows = listing.get("workflows") if isinstance(listing, dict) else None
    if not isinstance(workflows, list):
        raise TypeError("Could not read trusted workflow inventory")
    by_path = {item.get("path"): item for item in workflows}
    inventory = []
    for path in REQUIRED_WORKFLOW_PATHS:
        item = by_path.get(path)
        if not item or item.get("state") != "active":
            raise ValueError(
                f"Required trusted workflow is missing or inactive: {path}"
            )
        inventory.append(
            {
                "path": path,
                "workflow_id": item.get("id"),
                "app_slug": "github-actions",
                "event": "pull_request",
            }
        )
    validate_inventory(inventory)
    return inventory


def _validate_live_pr(
    github: Any, pr_number: int, target_sha: str, base_sha: str
) -> dict[str, Any]:
    from obi_adoption_repair import managed_branch

    pr = github.request("GET", f"/pulls/{pr_number}")
    author = pr.get("user") or {}
    if author.get("login") != "grafana-beyla-bot[bot]" or author.get("id") != 261436639:
        raise ValueError(
            "managed adoption PR is not owned by the trusted updater GitHub App"
        )
    if pr.get("state") != "open":
        raise ValueError("managed adoption PR is not open")
    if (
        pr.get("base", {}).get("ref") != "main"
        or pr.get("base", {}).get("sha") != base_sha
    ):
        raise ValueError("PR base changed or does not match the immutable status state")
    if pr.get("head", {}).get("repo", {}).get("full_name") != "grafana/beyla":
        raise ValueError("PR head is not in the canonical repository")
    head_branch = pr.get("head", {}).get("ref")
    if head_branch != managed_branch(target_sha):
        raise ValueError("PR branch does not match its immutable OBI target")
    marker = (
        f"<!-- grafana-beyla-obi-adoption:v1 target={target_sha} base={base_sha} -->"
    )
    if (pr.get("body") or "").count(marker) != 1:
        raise ValueError(
            "PR body does not contain exactly one matching adoption marker"
        )
    current_main = github.request("GET", "/commits/main").get("sha")
    if current_main != base_sha:
        raise ValueError("main advanced beyond the immutable adoption base")
    head_sha = pr.get("head", {}).get("sha")
    merge_sha = pr.get("merge_commit_sha")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("PR head SHA is unavailable")
    if not isinstance(merge_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ValueError("current PR merge SHA is unavailable")
    pin = github.request("GET", f"/contents/.obi-src?ref={head_sha}")
    if pin.get("type") != "submodule" or pin.get("sha") != target_sha:
        raise ValueError("current PR OBI gitlink no longer matches the exact target")
    return {"pr": pr, "head_sha": head_sha, "merge_sha": merge_sha}


def _read_required_runs(
    github: Any,
    *,
    pr_number: int,
    head_sha: str,
    base_sha: str,
    merge_sha: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    workflows = _workflow_inventory(github)
    by_id = {item["workflow_id"]: item for item in workflows}
    page = 1
    selected: list[dict[str, Any]] = []
    while page <= 10:
        result = github.request(
            "GET",
            f"/actions/runs?head_sha={head_sha}&event=pull_request&per_page=100&page={page}",
        )
        batch = result.get("workflow_runs", [])
        if not isinstance(batch, list):
            raise TypeError("Could not read PR workflow runs")
        for run in batch:
            item = by_id.get(run.get("workflow_id"))
            if not item:
                continue
            associations = run.get("pull_requests") or []
            matching_pr = next(
                (row for row in associations if row.get("number") == pr_number), None
            )
            if not matching_pr:
                continue
            selected.append(
                {
                    "workflow_path": item["path"],
                    "workflow_id": run.get("workflow_id"),
                    "app_slug": "github-actions"
                    if run.get("event") == "pull_request"
                    else None,
                    "event": run.get("event"),
                    "pr_number": pr_number,
                    "target_sha": None,
                    "pr_head_sha": matching_pr.get("head", {}).get("sha"),
                    "base_sha": matching_pr.get("base", {}).get("sha"),
                    "merge_sha": merge_sha,
                    # The required workflow files use the default pull_request
                    # checkout (GITHUB_SHA is the synthetic merge commit). Require
                    # that exact current merge SHA, not a prior/branch-only check.
                    "run_head_sha": run.get("head_sha"),
                    "expected_test_sha": merge_sha,
                    "test_sha_basis": "trusted-default-pull-request-merge-checkout",
                    "check_suite_id": run.get("check_suite_id"),
                    "run_id": run.get("id"),
                    "attempt": run.get("run_attempt", 1),
                    "status": run.get("status"),
                    "conclusion": run.get("conclusion"),
                }
            )
        if len(batch) < 100:
            break
        page += 1
    if page > 10:
        raise ValueError("Workflow run inventory exceeded safe pagination bound")

    # Run records do not contain the check app. Bind each expected workflow
    # run to its check suite and require the GitHub Actions app identity.
    all_checks = []
    page = 1
    while page <= 10:
        result = github.request(
            "GET",
            f"/commits/{head_sha}/check-runs?per_page=100&page={page}",
        )
        batch = result.get("check_runs", [])
        if not isinstance(batch, list):
            raise TypeError("Could not read check runs")
        all_checks.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    if page > 10:
        raise ValueError("Check-run inventory exceeded safe pagination bound")

    # The API run list has a stable check_suite_id. If a suite is missing, set
    # the app to unknown so the evaluator waits/blocks rather than trusting it.
    for run in selected:
        suite_id = run.get("check_suite_id")
        slugs = {
            check.get("app", {}).get("slug")
            for check in all_checks
            if check.get("check_suite", {}).get("id") == suite_id
        }
        run["app_slug"] = "github-actions" if slugs == {"github-actions"} else None
    return workflows, selected


def _load_comment_state(
    github: Any, pr_number: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    from obi_adoption_repair import extract_state_comment, validate_reservation

    comments = _status_comments(github, pr_number)
    if len(comments) != 1 or not _author_is_trusted(comments[0]):
        raise ValueError(
            "canonical status comment is missing, duplicated, or not trusted"
        )
    state = extract_state_comment(comments[0].get("body", ""))
    if state.get("schema_version") != 1 or state.get("pr_number") != pr_number:
        raise ValueError("canonical status state is malformed or belongs to another PR")
    target = state.get("target_sha")
    if (
        not isinstance(target, str)
        or managed_target(f"update-obi-adoption-{target}") != target
    ):
        raise ValueError("canonical status target is malformed")
    for key in ("base_sha", "head_sha", "merge_sha"):
        value = state.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError(f"canonical status {key} is malformed")
    if state.get("stage") not in {
        "waiting",
        "repairing",
        "ready-for-human-review",
        "blocked",
        "superseded",
    }:
        raise ValueError("canonical status stage is unsupported")
    budget = state.get("repair_budget")
    if not isinstance(budget, dict):
        raise TypeError("canonical status repair budget is malformed")
    used = budget.get("used")
    if isinstance(used, bool) or not isinstance(used, int) or not 0 <= used <= 2:
        raise ValueError("canonical status repair count is malformed")
    if budget.get("max") != 2:
        raise ValueError("canonical status repair limit is not the trusted pilot limit")
    reservation = state.get("reservation")
    if not isinstance(reservation, dict):
        raise TypeError("canonical status reservation is malformed")
    if state.get("stage") == "repairing":
        validate_reservation(
            state,
            pr_number=pr_number,
            target_sha=target,
            base_sha=state["base_sha"],
            head_sha=state["head_sha"],
            attempt=used,
            max_attempts=2,
            reservation_digest=reservation.get("digest", ""),
        )
    elif reservation != {"attempt": 0, "digest": None}:
        raise ValueError(
            "inactive status state must not carry a live repair reservation"
        )
    validate_inventory(state.get("required_checks", []))
    return comments[0], state


def _edit_status(
    github: Any, comment: dict[str, Any], state: dict[str, Any], text: str
) -> None:
    from obi_adoption_repair import encode_state_comment

    # Re-read the exact comment immediately before mutation; this is the API
    # compare-and-swap guard under the shared non-canceling writer lock.
    current = github.request("GET", f"/issues/comments/{comment['id']}")
    if current.get("body") != comment.get("body") or not _author_is_trusted(current):
        raise ValueError(
            "status comment changed or lost trusted ownership; refusing stale update"
        )
    live = _validate_live_pr(
        github,
        state["pr_number"],
        state["target_sha"],
        state["base_sha"],
    )
    if live["head_sha"] != state.get("head_sha") or live["merge_sha"] != state.get(
        "merge_sha"
    ):
        raise ValueError(
            "PR head/merge changed before status edit; refusing stale update"
        )
    github.request(
        "PATCH",
        f"/issues/comments/{comment['id']}",
        {"body": encode_state_comment(state, text)},
    )


def _emit_outputs(path: str | None, outputs: dict[str, Any]) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as output:
            output.writelines(
                f"{key}={str(value).lower() if isinstance(value, bool) else value}\n"
                for key, value in outputs.items()
            )
    print(json.dumps(outputs, sort_keys=True))


def _format_status_summary(
    *,
    state: dict[str, Any],
    decision: dict[str, Any],
    pr_number: int,
    target_sha: str,
) -> str:
    stage = state.get("stage", "blocked")
    labels = {
        "waiting": "Waiting for required checks",
        "repairing": "Bounded repair in progress",
        "ready-for-human-review": "Ready for human review",
        "blocked": "Blocked; human action required",
        "superseded": "Superseded; owner hold",
    }
    budget = state.get("repair_budget", {})
    lines = [
        "## OBI adoption status",
        f"- Stage: **{labels.get(stage, 'Unknown')}**",
        f"- PR: #{pr_number}; target OBI SHA: `{target_sha}`",
        f"- Current PR head: `{state.get('head_sha', '')}`; base SHA: `{state.get('base_sha', '')}`",
        f"- Repair budget: {budget.get('used', 0)}/{budget.get('max', 2)}",
        f"- Deadline: `{state.get('deadline_utc', 'unknown')}`",
    ]
    links: list[str] = []
    seen: set[int] = set()
    for run in state.get("evidence", []):
        run_id = run.get("run_id")
        if not isinstance(run_id, int) or run_id in seen:
            continue
        seen.add(run_id)
        conclusion = run.get("conclusion") or run.get("status") or "unknown"
        path = run.get("workflow_path", "required workflow")
        links.append(
            f"[{path} ({conclusion})](https://github.com/grafana/beyla/actions/runs/{run_id})"
        )
    if links:
        lines.append("- Required check evidence: " + ", ".join(links[:12]))
    else:
        lines.append("- Required check evidence: incomplete or unavailable")
    reason = decision.get("reason", "")
    if reason:
        lines.append(f"- Decision reason: `{reason}`")
    if stage == "ready-for-human-review":
        lines.append(
            "- Next action: team review and human merge. This status does not change draft state or request reviewers."
        )
    elif stage == "repairing":
        lines.append(
            "- Next action: wait for the bounded compatibility repair and its fresh checks; no CI wait holds the writer lock."
        )
    elif stage == "waiting":
        lines.append(
            "- Next action: wait for all required current-head checks or the recorded deadline."
        )
    elif stage == "superseded":
        lines.append(
            "- Next action: owner review. Main already pins this exact OBI target; do not close, retarget, or change PR draft state automatically."
        )
    else:
        lines.append(
            "- Next action: owner investigation; automation will not infer missing evidence as green or retry a terminal failure."
        )
    lines.append(
        "This is a point-in-time status only; GitHub PR/check state is authoritative."
    )
    return "\n".join(lines)


def initialize_status(
    *,
    pr_number: int,
    target_sha: str,
    base_sha: str,
    head_sha: str,
    token: str,
    new_pr: bool,
) -> dict[str, Any]:
    from obi_adoption_repair import (
        STATUS_MARKER,
        encode_state_comment,
    )

    github = _trusted_api(token)
    if new_pr and os.environ.get(WRITER_FLAG) != "true":
        raise ValueError(
            "new adoption status initialization is disabled by the writer gate"
        )
    live = _validate_live_pr(github, pr_number, target_sha, base_sha)
    if live["head_sha"] != head_sha:
        raise ValueError("PR head changed before status initialization")
    comments = _status_comments(github, pr_number)
    if comments:
        if len(comments) != 1 or not _author_is_trusted(comments[0]):
            raise ValueError(
                "existing canonical status comment is not uniquely trusted"
            )
        from obi_adoption_repair import extract_state_comment

        state = extract_state_comment(comments[0].get("body", ""))
        if (
            state.get("schema_version") != 1
            or state.get("pr_number") != pr_number
            or state.get("target_sha") != target_sha
            or state.get("base_sha") != base_sha
        ):
            raise ValueError("existing canonical state does not match the new PR")
        return {"initialized": False, "comment_id": comments[0]["id"]}
    if not new_pr:
        raise ValueError(
            "status state is missing; only new-PR creation may initialize it"
        )

    inventory = _workflow_inventory(github)
    deadline = datetime.now(timezone.utc) + timedelta(hours=6)
    state = {
        "schema_version": 1,
        "pr_number": pr_number,
        "target_sha": target_sha,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "merge_sha": live["merge_sha"],
        "stage": "waiting",
        "repair_budget": {"used": 0, "max": 2},
        "reservation": {"attempt": 0, "digest": None},
        "deadline_utc": deadline.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "required_checks": inventory,
        "evidence": [],
        "repair_failed_heads": [],
        "last_failure_run_ids": [],
    }
    # Re-read before create: a competing initializer must not make a duplicate.
    if _status_comments(github, pr_number):
        raise ValueError("status comment appeared concurrently; refusing duplicate")
    body = encode_state_comment(
        state,
        f"OBI adoption target `{target_sha}` is being checked. This status does not change PR draft state, request review, or merge.",
    )
    created = github.request("POST", f"/issues/{pr_number}/comments", {"body": body})
    if (
        not created
        or not _author_is_trusted(created)
        or STATUS_MARKER not in created.get("body", "")
    ):
        raise ValueError("GitHub did not create the expected trusted status comment")
    after = _status_comments(github, pr_number)
    if len(after) != 1 or after[0].get("id") != created.get("id"):
        raise ValueError(
            "status comment creation raced with another writer; human reconciliation is required"
        )
    return {"initialized": True, "comment_id": created.get("id")}


def reconcile_status(
    *,
    pr_number: int,
    target_sha: str,
    base_sha: str,
    token: str,
    workflow_run_id: int | None,
    output_path: str | None,
    no_repair: bool = False,
    worker_finished: bool = False,
    allow_repair: bool = False,
) -> dict[str, Any]:
    from obi_adoption_repair import state_digest

    github = _trusted_api(token)
    try:
        comment, prior = _load_comment_state(github, pr_number)
        if prior.get("target_sha") != target_sha or prior.get("base_sha") != base_sha:
            raise ValueError(
                "canonical status target/base is inconsistent; fail closed"
            )
        live = _validate_live_pr(github, pr_number, target_sha, base_sha)
        head_sha, merge_sha = live["head_sha"], live["merge_sha"]
        if prior.get("repair_budget") != {
            "used": prior.get("repair_budget", {}).get("used"),
            "max": 2,
        }:
            raise ValueError("canonical repair budget is corrupt")
        prior_head_sha = prior.get("head_sha")
        if prior_head_sha != head_sha:
            # A changed PR head is re-evaluated against current checks without
            # resetting the PR+target repair budget or carrying old evidence.
            prior["head_sha"] = head_sha
            prior["stage"] = "waiting"
            prior["reservation"] = {"attempt": 0, "digest": None}
            prior["evidence"] = []
            prior["deadline_utc"] = (
                (datetime.now(timezone.utc) + timedelta(hours=6))
                .isoformat(timespec="seconds")
                .replace("+00:00", "Z")
            )
        elif prior.get("stage") == "repairing" and not worker_finished:
            # The exact same event/head must not rewrite the digest-bearing
            # reservation or launch a duplicate worker. The workflow's
            # post-worker finalizer clears this reservation after re-reading.
            reservation = prior.get("reservation") or {}
            outputs = {
                "stage": "repairing",
                "should_repair": False,
                "pr_number": pr_number,
                "obi_sha": target_sha,
                "expected_head": head_sha,
                "expected_base": base_sha,
                "trigger_run_id": workflow_run_id or 0,
                "attempt": reservation.get("attempt", 0),
                "max_attempts": 2,
                "reservation_digest": reservation.get("digest", ""),
                "reason": "repair-already-reserved",
            }
            _emit_outputs(output_path, outputs)
            return outputs

        inventory, runs = _read_required_runs(
            github,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            merge_sha=merge_sha,
        )
        current_time = (
            datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        previous_inventory = validate_inventory(prior["required_checks"])
        current_inventory = validate_inventory(inventory)
        inventory_matches = all(
            previous_inventory[path].get("workflow_id")
            == current_inventory[path].get("workflow_id")
            and previous_inventory[path].get("app_slug") == "github-actions"
            and previous_inventory[path].get("event") == "pull_request"
            for path in REQUIRED_WORKFLOW_PATHS
        )
        if not inventory_matches:
            decision = {
                "stage": "blocked",
                "reason": "required-workflow-identity-changed",
                "missing": [],
                "incomplete": [],
                "invalid": list(REQUIRED_WORKFLOW_PATHS),
                "unknown_terminal": [],
                "repairable_run_ids": [],
            }
        else:
            decision = evaluate_required_checks(
                inventory=inventory,
                runs=runs,
                pr_number=pr_number,
                target_sha=target_sha,
                head_sha=head_sha,
                base_sha=base_sha,
                merge_sha=merge_sha,
                observed_at=current_time,
                deadline=prior.get("deadline_utc", ""),
            )
        evidence = [
            {
                "workflow_path": run["workflow_path"],
                "workflow_id": run["workflow_id"],
                "run_id": run["run_id"],
                "attempt": run["attempt"],
                "run_head_sha": run["run_head_sha"],
                "expected_test_sha": run["expected_test_sha"],
                "test_sha_basis": run["test_sha_basis"],
                "pr_head_sha": run["pr_head_sha"],
                "base_sha": run["base_sha"],
                "merge_sha": run["merge_sha"],
                "app_slug": run["app_slug"],
                "event": run["event"],
                "status": run["status"],
                "conclusion": run["conclusion"],
            }
            for run in runs
        ]
        prior["required_checks"] = inventory
        prior["evidence"] = evidence
        prior["head_sha"] = head_sha
        prior["merge_sha"] = merge_sha
        prior["base_sha"] = base_sha
        prior["updated_at"] = current_time
        prior["stage"] = decision["stage"]
        should_repair = False
        attempt = 0
        reservation_digest = ""

        if (
            worker_finished
            and prior_head_sha == head_sha
            and decision["stage"] != "ready-for-human-review"
        ):
            # A worker that completed without advancing the exact PR head did
            # not produce a candidate for retesting. Preserve its consumed
            # budget and stop for a human instead of retrying stale failures.
            prior["stage"] = "blocked"
            prior["reservation"] = {"attempt": 0, "digest": None}
            failed_heads = prior.setdefault("repair_failed_heads", [])
            if head_sha not in failed_heads:
                failed_heads.append(head_sha)
            decision["reason"] = "repair-finished-without-new-head"
        elif decision["stage"] == "ready-for-human-review":
            # A completed reservation no longer authenticates any future work.
            prior["reservation"] = {"attempt": 0, "digest": None}
        elif decision["stage"] == "repairable":
            if live["pr"].get("draft") is not True:
                prior["stage"] = "blocked"
                prior["reservation"] = {"attempt": 0, "digest": None}
                decision["reason"] = (
                    "PR-is-no-longer-draft; repair stops for human review"
                )
            elif not allow_repair or no_repair:
                prior["stage"] = "blocked"
                prior["reservation"] = {"attempt": 0, "digest": None}
                decision["reason"] = "automatic-repair-disabled-by-repository-gates"
            elif head_sha in prior.get("repair_failed_heads", []):
                prior["stage"] = "blocked"
                prior["reservation"] = {"attempt": 0, "digest": None}
                decision["reason"] = "repair-head-already-terminal"
            else:
                budget = next_repair_budget(
                    prior_state={**prior, "stage": "blocked"},
                    pr_number=pr_number,
                    target_sha=target_sha,
                    base_sha=base_sha,
                    head_sha=head_sha,
                    max_attempts=2,
                )
                if budget["allowed"]:
                    attempt = budget["attempt"]
                    prior["stage"] = "repairing"
                    prior["repair_budget"] = {"used": attempt, "max": 2}
                    prior["reservation"] = {"attempt": attempt, "digest": None}
                    prior["last_failure_run_ids"] = decision["repairable_run_ids"]
                    reservation_digest = state_digest(prior)
                    prior["reservation"]["digest"] = reservation_digest
                    should_repair = True
                else:
                    prior["stage"] = "blocked"
                    decision["reason"] = "repair-budget-exhausted"

        summary = _format_status_summary(
            state=prior,
            decision=decision,
            pr_number=pr_number,
            target_sha=target_sha,
        )

        # Validate current PR and comment immediately before status mutation.
        live_again = _validate_live_pr(github, pr_number, target_sha, base_sha)
        if live_again["head_sha"] != head_sha or live_again["merge_sha"] != merge_sha:
            raise ValueError(
                "PR head/base/merge changed during reconciliation; retry from fresh GitHub truth"
            )
        _edit_status(github, comment, prior, summary)
        outputs = {
            "stage": prior["stage"],
            "should_repair": should_repair,
            "pr_number": pr_number,
            "obi_sha": target_sha,
            "expected_head": head_sha,
            "expected_base": base_sha,
            "trigger_run_id": (
                decision["repairable_run_ids"][0]
                if should_repair and decision.get("repairable_run_ids")
                else workflow_run_id or 0
            ),
            "attempt": attempt,
            "max_attempts": 2,
            "reservation_digest": reservation_digest,
            "reason": decision.get("reason", ""),
        }
    except (
        RepairError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        RuntimeError,
    ) as exc:
        # Fail closed. Do not create missing state here and do not print API
        # response bodies, credentials, or untrusted comment text.
        outputs = {
            "stage": "blocked",
            "should_repair": False,
            "pr_number": pr_number,
            "obi_sha": target_sha,
            "expected_head": "",
            "expected_base": base_sha,
            "trigger_run_id": workflow_run_id or 0,
            "attempt": 0,
            "max_attempts": 2,
            "reservation_digest": "",
            "reason": str(exc),
        }
    _emit_outputs(output_path, outputs)
    return outputs


def reconcile_workflow_event(
    *,
    workflow_run_id: int,
    token: str,
    output_path: str | None,
    allow_repair: bool,
) -> dict[str, Any]:
    """Resolve the completed workflow_run to current PR metadata, then reconcile."""
    github = _trusted_api(token)
    run = github.request("GET", f"/actions/runs/{workflow_run_id}")
    repository = run.get("repository", {}).get("full_name")
    if repository != "grafana/beyla":
        raise ValueError("workflow run is not from grafana/beyla")
    branch = run.get("head_branch", "")
    target = managed_target(branch)
    if target is None:
        raise ValueError("workflow run is not for a validated managed adoption branch")
    associations = run.get("pull_requests") or []
    if len(associations) != 1:
        raise ValueError("workflow run does not resolve to exactly one PR")
    pr_number = associations[0].get("number")
    if not isinstance(pr_number, int) or pr_number <= 0:
        raise ValueError("workflow run PR number is invalid")
    pr = github.request("GET", f"/pulls/{pr_number}")
    identity = validate_pr_identity(
        branch=branch,
        body=pr.get("body") or "",
        pr_number=pr_number,
        expected_pr_number=pr_number,
        base_ref=pr.get("base", {}).get("ref", ""),
        head_repository=pr.get("head", {}).get("repo", {}).get("full_name", ""),
        repository=repository,
    )
    return reconcile_status(
        pr_number=pr_number,
        target_sha=identity["target_sha"],
        base_sha=identity["base_sha"],
        token=token,
        workflow_run_id=workflow_run_id,
        output_path=output_path,
        allow_repair=allow_repair,
    )


def reconcile_superseded(
    *, pr_number: int, target_sha: str, token: str
) -> dict[str, Any]:
    """Mark exact current-main adoption as superseded; do status-only human hold."""
    from obi_adoption_repair import encode_state_comment

    github = _trusted_api(token)
    comment, state = _load_comment_state(github, pr_number)
    if state.get("target_sha") != target_sha:
        raise ValueError("superseded target differs from the canonical PR state")
    pr = github.request("GET", f"/pulls/{pr_number}")
    author = pr.get("user") or {}
    if author.get("login") != "grafana-beyla-bot[bot]" or author.get("id") != 261436639:
        raise ValueError("superseded PR is not owned by the trusted updater GitHub App")
    if pr.get("state") != "open":
        raise ValueError("superseded PR is not open")
    if pr.get("head", {}).get("repo", {}).get("full_name") != "grafana/beyla":
        raise ValueError("superseded PR is not in the canonical repository")
    if pr.get("head", {}).get("ref") != f"update-obi-adoption-{target_sha}":
        raise ValueError("superseded PR branch does not match the exact target")
    if pr.get("base", {}).get("ref") != "main":
        raise ValueError("superseded PR does not target main")
    marker = (
        f"<!-- grafana-beyla-obi-adoption:v1 target={target_sha} "
        f"base={state['base_sha']} -->"
    )
    if (pr.get("body") or "").count(marker) != 1:
        raise ValueError("superseded PR marker does not match canonical status state")
    head_sha = pr.get("head", {}).get("sha")
    merge_sha = pr.get("merge_commit_sha")
    if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise ValueError("superseded PR head is unavailable")
    if not isinstance(merge_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ValueError("superseded PR merge SHA is unavailable")
    current_main = github.request("GET", "/commits/main").get("sha")
    if pr.get("base", {}).get("sha") != current_main:
        raise ValueError("PR base and current main differ; supersession is unknown")
    main_pin = github.request("GET", f"/contents/.obi-src?ref={current_main}")
    if main_pin.get("type") != "submodule" or main_pin.get("sha") != target_sha:
        raise ValueError("current main does not pin the exact selected OBI target")
    candidate_pin = github.request("GET", f"/contents/.obi-src?ref={head_sha}")
    if (
        candidate_pin.get("type") != "submodule"
        or candidate_pin.get("sha") != target_sha
    ):
        raise ValueError("superseded PR source pin changed from the exact target")

    state["stage"] = "superseded"
    state["head_sha"] = head_sha
    state["merge_sha"] = merge_sha
    state["superseded_main_sha"] = current_main
    state["reservation"] = {"attempt": 0, "digest": None}
    state["updated_at"] = (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    summary = (
        f"## OBI adoption status\n- Stage: **Superseded; human hold**\n"
        f"- PR: #{pr_number}; target OBI SHA: `{target_sha}`\n"
        f"- Current main `{current_main}` already pins this exact OBI target.\n"
        f"- Existing PR head: `{head_sha}`; original base identity: `{state['base_sha']}`.\n"
        f"- Repair budget remains {state['repair_budget']['used']}/{state['repair_budget']['max']}; no repair reservation was made.\n"
        "- Next action: owner review. No automatic close, retarget, draft-state change, reviewer request, or merge."
    )
    current_comment = github.request("GET", f"/issues/comments/{comment['id']}")
    if current_comment.get("body") != comment.get("body") or not _author_is_trusted(
        current_comment
    ):
        raise ValueError(
            "status comment changed or lost trusted ownership; refusing stale update"
        )
    # Re-read exact source/main facts immediately before the status-only edit.
    if github.request("GET", "/commits/main").get("sha") != current_main:
        raise ValueError("main changed during superseded status reconciliation")
    verify_pin = github.request("GET", f"/contents/.obi-src?ref={current_main}")
    if verify_pin.get("type") != "submodule" or verify_pin.get("sha") != target_sha:
        raise ValueError(
            "main source pin changed during superseded status reconciliation"
        )
    pr_again = github.request("GET", f"/pulls/{pr_number}")
    author_again = pr_again.get("user") or {}
    if (
        pr_again.get("state") != "open"
        or author_again.get("login") != "grafana-beyla-bot[bot]"
        or author_again.get("id") != 261436639
        or pr_again.get("head", {}).get("repo", {}).get("full_name") != "grafana/beyla"
        or pr_again.get("base", {}).get("sha") != current_main
        or pr_again.get("head", {}).get("sha") != head_sha
        or pr_again.get("merge_commit_sha") != merge_sha
        or pr_again.get("head", {}).get("ref") != f"update-obi-adoption-{target_sha}"
        or (pr_again.get("body") or "").count(marker) != 1
    ):
        raise ValueError("PR identity changed during superseded status reconciliation")
    candidate_pin = github.request("GET", f"/contents/.obi-src?ref={head_sha}")
    if (
        candidate_pin.get("type") != "submodule"
        or candidate_pin.get("sha") != target_sha
    ):
        raise ValueError(
            "PR source pin changed during superseded status reconciliation"
        )
    github.request(
        "PATCH",
        f"/issues/comments/{comment['id']}",
        {"body": encode_state_comment(state, summary)},
    )
    return {
        "stage": "superseded",
        "pr_number": pr_number,
        "target_sha": target_sha,
        "main_sha": current_main,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trusted OBI adoption supervisor/status helpers"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init-state")
    init.add_argument("--pr-number", type=int, required=True)
    init.add_argument("--target-sha", required=True)
    init.add_argument("--base-sha", required=True)
    init.add_argument("--head-sha", required=True)
    init.add_argument("--new-pr", action="store_true")

    reconcile = subparsers.add_parser("reconcile")
    reconcile.add_argument("--pr-number", type=int, required=True)
    reconcile.add_argument("--target-sha", required=True)
    reconcile.add_argument("--base-sha", required=True)
    reconcile.add_argument("--workflow-run-id", type=int)
    reconcile.add_argument("--output")
    reconcile.add_argument("--no-repair", action="store_true")
    reconcile.add_argument("--worker-finished", action="store_true")
    reconcile.add_argument("--allow-repair", action="store_true")

    event = subparsers.add_parser("reconcile-event")
    event.add_argument("--workflow-run-id", type=int, required=True)
    event.add_argument("--output")
    event.add_argument("--allow-repair", action="store_true")

    superseded = subparsers.add_parser("reconcile-superseded")
    superseded.add_argument("--pr-number", type=int, required=True)
    superseded.add_argument("--target-sha", required=True)

    args = parser.parse_args(argv)
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        print("status blocked: trusted GitHub token is unavailable", file=sys.stderr)
        return 1
    try:
        if args.command == "init-state":
            result = initialize_status(
                pr_number=args.pr_number,
                target_sha=args.target_sha,
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                token=token,
                new_pr=args.new_pr,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "reconcile":
            result = reconcile_status(
                pr_number=args.pr_number,
                target_sha=args.target_sha,
                base_sha=args.base_sha,
                token=token,
                workflow_run_id=args.workflow_run_id,
                output_path=args.output,
                no_repair=args.no_repair,
                worker_finished=args.worker_finished,
                allow_repair=repair_gate_enabled(allow_repair=args.allow_repair),
            )
            return 0 if result["stage"] != "blocked" else 1
        if args.command == "reconcile-event":
            result = reconcile_workflow_event(
                workflow_run_id=args.workflow_run_id,
                token=token,
                output_path=args.output,
                allow_repair=repair_gate_enabled(allow_repair=args.allow_repair),
            )
            return 0 if result["stage"] != "blocked" else 1
        if args.command == "reconcile-superseded":
            result = reconcile_superseded(
                pr_number=args.pr_number,
                target_sha=args.target_sha,
                token=token,
            )
            print(json.dumps(result, sort_keys=True))
            return 0
    except (
        RepairError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        RuntimeError,
    ) as exc:
        print(f"status blocked: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
