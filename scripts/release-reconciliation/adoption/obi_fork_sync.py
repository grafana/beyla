"""Read-only planning and guarded PR continuation for the OBI fork sync."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

SHA = re.compile(r"^[0-9a-f]{40}$")
REQUEST_TITLE = re.compile(
    r"^OBI fork sync target ([0-9a-f]{40}) request ([1-9][0-9]*)$"
)
ADOPTION_TITLE = re.compile(
    r"^OBI adoption target ([0-9a-f]{40}) request ([1-9][0-9]*)$"
)
PR_MARKER = re.compile(
    r"<!-- grafana-obi-fork-sync:v1 target=([0-9a-f]{40}) base=([0-9a-f]{40}) -->"
)
ADOPTION_MARKER = re.compile(
    r"<!-- grafana-beyla-obi-adoption:v1 target=([0-9a-f]{40}) base=([0-9a-f]{40}) -->"
)
STATUS_MARKER = "<!-- grafana-obi-fork-sync-status:v1 -->"
STATE_MARKER = "<!-- grafana-obi-fork-sync-state:v1"
FORK_REPO = "grafana/opentelemetry-ebpf-instrumentation"
BEYLA_REPO = "grafana/beyla"
FORK_WORKFLOW = "bot_sync-obi-fork.yml"
ADOPTION_WORKFLOW = "bot_sync-obi-submodule.yml"
BOT_LOGIN = "grafana-beyla-bot[bot]"
BOT_ID = 261436639
MAX_PAGES = 5
MAX_CONTINUATIONS = 32


class ForkSyncError(RuntimeError):
    """A fail-closed fork-sync condition suitable for an Actions summary."""


def valid_sha(value: object) -> bool:
    return isinstance(value, str) and SHA.fullmatch(value) is not None


def request_title(target_sha: str, origin_run_id: str) -> str:
    if not valid_sha(target_sha) or not str(origin_run_id).isdigit():
        raise ForkSyncError("Request title requires a full OBI SHA and run ID.")
    return f"OBI fork sync target {target_sha} request {origin_run_id}"


def adoption_title(target_sha: str, origin_run_id: str) -> str:
    if not valid_sha(target_sha) or not str(origin_run_id).isdigit():
        raise ForkSyncError(
            "Adoption title requires a full OBI SHA and request run ID."
        )
    return f"OBI adoption target {target_sha} request {origin_run_id}"


def parse_request_run(run: dict) -> dict | None:
    """Parse a target request only from the expected workflow-run identity."""
    match = REQUEST_TITLE.fullmatch(run.get("display_title", ""))
    if match is None:
        return None
    if run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main":
        return None
    if run.get("status") not in {"queued", "in_progress", "completed"}:
        return None
    return {
        "target_sha": match.group(1),
        "origin_run_id": match.group(2),
        "run_id": str(run.get("id", "")),
        "created_at": run.get("created_at", ""),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
    }


def parse_pr_marker(pr: dict) -> dict | None:
    """Return the immutable target/base only for an exact managed PR marker."""
    match = PR_MARKER.search(pr.get("body") or "")
    if match is None:
        return None
    target, base = match.groups()
    expected_branch = f"sync-obi-upstream-{target}"
    if pr.get("head", {}).get("ref") != expected_branch:
        return None
    if pr.get("head", {}).get("repo", {}).get("full_name") != FORK_REPO:
        return None
    if pr.get("head", {}).get("sha") != target:
        return None
    if pr.get("base", {}).get("ref") != "main":
        return None
    if pr.get("base", {}).get("repo", {}).get("full_name") != FORK_REPO:
        return None
    return {"target_sha": target, "base_sha": base}


def choose_sync_action(
    *,
    target_sha: str,
    fork_main_sha: str,
    object_visible: bool,
    target_is_ancestor: bool,
    compare_status: str | None,
    merge_base_sha: str | None = None,
    managed_merge_base: bool = False,
    managed_open: list[dict],
    exact_closed: list[dict],
    branch_exists: bool,
) -> dict:
    """Plan only; callers provide complete, authoritative GitHub facts."""
    if not valid_sha(target_sha) or not valid_sha(fork_main_sha):
        return {
            "action": "unknown",
            "reason": "A full selected or fork-main SHA is unavailable.",
        }
    if managed_open:
        if len(managed_open) != 1:
            return {
                "action": "hold",
                "reason": "Multiple managed fork-sync PRs are open.",
            }
        marker = parse_pr_marker(managed_open[0])
        if not marker:
            return {
                "action": "hold",
                "reason": "The open fork-sync PR identity is untrusted.",
            }
        return {
            "action": "observe" if marker["target_sha"] == target_sha else "defer",
            "reason": "Preserve the existing managed fork-sync PR; never retarget it.",
            "pr_number": managed_open[0].get("number"),
            "active_target_sha": marker["target_sha"],
        }
    if any(
        pr.get("state") == "closed" and not pr.get("merged_at") for pr in exact_closed
    ):
        return {
            "action": "hold",
            "reason": "This exact target was previously closed without merge.",
        }
    if not object_visible:
        return {
            "action": "hold",
            "reason": "The exact source commit is not visible in the fork; do not import or guess it.",
        }
    if target_is_ancestor:
        return {
            "action": "synced",
            "reason": "The exact selected commit is already reachable from fork main.",
        }
    if branch_exists:
        return {
            "action": "hold",
            "reason": "The managed branch exists without a matching trusted PR.",
        }
    initial_fast_forward = compare_status == "ahead" and merge_base_sha == fork_main_sha
    recurring_managed_base = compare_status == "diverged" and managed_merge_base
    if not (initial_fast_forward or recurring_managed_base):
        return {
            "action": "hold",
            "reason": "Fork/source history is not a verified initial or recurring managed sync relation.",
        }
    return {
        "action": "create",
        "reason": "The exact visible source can be proposed without changing fork main.",
    }


def select_requests(runs: list[dict]) -> dict:
    """Collapse duplicate workflow runs; conflicting targets per origin fail closed."""
    grouped: dict[str, set[str]] = {}
    records: dict[tuple[str, str], list[dict]] = {}
    for run in runs:
        item = parse_request_run(run)
        if item is None:
            continue
        origin = item["origin_run_id"]
        target = item["target_sha"]
        grouped.setdefault(origin, set()).add(target)
        records.setdefault((origin, target), []).append(item)
    conflicts = sorted(
        origin for origin, targets in grouped.items() if len(targets) != 1
    )
    if conflicts:
        return {"complete": True, "conflicts": conflicts, "requests": []}
    requests_by_target: dict[str, list[dict]] = {}
    for origin, targets in grouped.items():
        target = next(iter(targets))
        matching = records[(origin, target)]
        matching.sort(key=lambda r: (r["created_at"], r["run_id"]))
        requests_by_target.setdefault(target, []).append(
            {
                "target_sha": target,
                "origin_run_id": origin,
                "request_run_id": matching[0]["run_id"],
                "duplicate_runs": [r["run_id"] for r in matching],
                "created_at": matching[0]["created_at"],
            }
        )
    requests = []
    for target, group in requests_by_target.items():
        group.sort(key=lambda r: (r["created_at"], r["origin_run_id"]))
        chosen = dict(group[0])
        chosen["origin_run_ids"] = [row["origin_run_id"] for row in group]
        chosen["duplicate_runs"] = [
            run_id for row in group for run_id in row["duplicate_runs"]
        ]
        requests.append(chosen)
    requests.sort(key=lambda r: (r["created_at"], r["target_sha"]))
    return {"complete": True, "conflicts": [], "requests": requests}


def ancestry_proven(comparison: dict, ancestor_sha: str) -> bool:
    """Require GitHub's comparison result and exact merge base, not tree equality."""
    if not valid_sha(ancestor_sha):
        return False
    return (
        comparison.get("status") in {"ahead", "identical"}
        and comparison.get("merge_base_commit", {}).get("sha") == ancestor_sha
    )


def parse_status_comment(body: str) -> dict:
    if not body.startswith(STATUS_MARKER + "\n") or STATE_MARKER not in body:
        raise ForkSyncError("Fork-sync status comment has an unknown schema.")
    try:
        state_json = body.split(STATE_MARKER, 1)[1].split("-->", 1)[0].strip()
        state = json.loads(state_json)
    except json.JSONDecodeError as exc:
        raise ForkSyncError("Fork-sync status comment JSON is malformed.") from exc
    if (
        not isinstance(state, dict)
        or state.get("schema_version") != 1
        or not isinstance(state.get("continuations"), list)
        or len(state["continuations"]) > MAX_CONTINUATIONS
    ):
        raise ForkSyncError(
            "Fork-sync status comment state is invalid or over its bounded size."
        )
    return state


def reserve_continuation(
    state: dict, target_sha: str, origin_ids: list[str]
) -> tuple[dict, str]:
    """Reserve once per exact target SHA; identical origins share one continuation."""
    if (
        not valid_sha(target_sha)
        or not origin_ids
        or any(not str(i).isdigit() for i in origin_ids)
    ):
        raise ForkSyncError(
            "Continuation needs one full target SHA and trusted origin run IDs."
        )
    records = state.get("continuations", [])
    matching = [record for record in records if record.get("target_sha") == target_sha]
    if matching:
        if len(matching) != 1:
            raise ForkSyncError("Duplicate target reservations exist; do not dispatch.")
        return state, "already-reserved"
    if len(records) >= MAX_CONTINUATIONS:
        raise ForkSyncError("Continuation ledger is full; stop and reconcile manually.")
    updated = dict(state)
    updated["continuations"] = [
        *records,
        {
            "target_sha": target_sha,
            "origin_run_ids": sorted(set(origin_ids)),
            "stage": "reserved",
            "dispatch_run_id": None,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    ]
    return updated, "reserved"


def set_dispatch_result(state: dict, target_sha: str, run_id: int | None) -> dict:
    updated = dict(state)
    rows = [dict(row) for row in state["continuations"]]
    matches = [row for row in rows if row.get("target_sha") == target_sha]
    if len(matches) != 1 or matches[0].get("stage") != "reserved":
        raise ForkSyncError(
            "No unique reserved continuation exists for dispatch result."
        )
    matches[0]["stage"] = "dispatched" if run_id is not None else "ambiguous"
    matches[0]["dispatch_run_id"] = run_id
    matches[0]["updated_at"] = datetime.now(timezone.utc).isoformat()
    updated["continuations"] = rows
    return updated


def update_continuation(
    state: dict, target_sha: str, stage: str, reason: str = ""
) -> dict:
    updated = dict(state)
    rows = [dict(row) for row in state["continuations"]]
    matches = [row for row in rows if row.get("target_sha") == target_sha]
    if len(matches) != 1:
        raise ForkSyncError("No unique continuation record exists for status update.")
    matches[0]["stage"] = stage
    matches[0]["reason"] = reason
    matches[0]["updated_at"] = datetime.now(timezone.utc).isoformat()
    updated["continuations"] = rows
    return updated


def continuation_target(
    request: dict, merged_prs: list[dict], fork_main_sha: str
) -> dict | None:
    """Choose a merged managed PR that proves the requested target reached fork main."""
    target = request.get("target_sha")
    if not valid_sha(target) or not valid_sha(fork_main_sha):
        return None
    for pr in merged_prs:
        marker = parse_pr_marker(pr)
        if marker is None or not pr.get("merged_at"):
            continue
        head_sha = pr.get("head", {}).get("sha")
        merge_sha = pr.get("merge_commit_sha")
        if not valid_sha(head_sha) or not valid_sha(merge_sha):
            continue
        # The caller supplies these independently verified ancestry facts.
        if not ancestry_proven(pr.get("target_comparison", {}), target):
            continue
        if not ancestry_proven(pr.get("merge_comparison", {}), target):
            continue
        if not ancestry_proven(pr.get("head_comparison", {}), head_sha):
            continue
        if not ancestry_proven(pr.get("fork_comparison", {}), merge_sha):
            continue
        return {
            "pr_number": pr.get("number"),
            "pr_target_sha": marker["target_sha"],
            "pr_head_sha": head_sha,
            "merge_sha": merge_sha,
            "target_sha": target,
        }
    return None


def render_status_comment(state: dict) -> str:
    parse_status_comment(
        STATUS_MARKER + "\n" + STATE_MARKER + "\n" + json.dumps(state) + "\n-->"
    )
    rows = state.get("continuations", [])
    latest = rows[-1] if rows else None
    if latest is None:
        summary = (
            "This managed fork PR is awaiting human review and merge-commit approval."
        )
    elif latest.get("stage") == "reserved":
        summary = (
            f"The exact target `{latest['target_sha']}` is reserved for one adoption continuation. "
            "If dispatch is ambiguous, it will not be retried automatically."
        )
    elif latest.get("stage") == "dispatched":
        run_id = latest.get("dispatch_run_id")
        link = (
            f"[workflow run](https://github.com/{BEYLA_REPO}/actions/runs/{run_id})"
            if run_id
            else "the workflow run"
        )
        summary = f"The exact target `{latest['target_sha']}` was dispatched to {link}; Beyla review and merge remain human-only."
    elif latest.get("stage") == "awaiting-beyla-human-merge":
        summary = (
            latest.get("reason")
            or "The Beyla adoption PR is awaiting human review and merge."
        )
    elif latest.get("stage") == "adopted":
        summary = "The exact target is now on Beyla main; this does not trigger a release or deployment."
    else:
        summary = (
            latest.get("reason")
            or "The continuation is blocked; human recovery is required."
        )
    encoded = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return f"{STATUS_MARKER}\n{summary}\n\n{STATE_MARKER}\n{encoded}\n-->"


@dataclass
class GitHubAPI:
    token: str
    repository: str

    def request(self, method: str, path: str, body: dict | None = None):
        data = (
            None if body is None else json.dumps(body, separators=(",", ":")).encode()
        )
        url = (
            path
            if path.startswith("https://api.github.com/")
            else f"https://api.github.com/repos/{self.repository}{path}"
        )
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": "grafana-beyla-obi-fork-sync",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                payload = response.read()
                return (json.loads(payload) if payload else None, response.status)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and method == "GET":
                return None, 404
            raise ForkSyncError(
                f"GitHub API {method} returned HTTP {exc.code}."
            ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise ForkSyncError(
                f"GitHub API {method} timed out; outcome may be ambiguous."
            ) from exc

    def get(self, path: str):
        return self.request("GET", path)[0]

    def paginate(
        self, path: str, max_pages: int = MAX_PAGES
    ) -> tuple[list[dict], bool]:
        values = []
        for page in range(1, max_pages + 1):
            separator = "&" if "?" in path else "?"
            batch = self.get(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ForkSyncError(
                    "GitHub returned an incomplete paginated inventory."
                )
            values.extend(batch)
            if len(batch) < 100:
                return values, True
        return values, False


def sha_of(repo: GitHubAPI, path: str) -> str:
    response = repo.get(path)
    sha = response.get("sha") if isinstance(response, dict) else None
    if not valid_sha(sha):
        raise ForkSyncError("GitHub did not return a full commit SHA.")
    return sha


def relation(repo: GitHubAPI, older: str, newer: str) -> tuple[bool, dict]:
    if not valid_sha(older) or not valid_sha(newer):
        return False, {}
    comparison = repo.get(f"/compare/{older}...{newer}")
    if not isinstance(comparison, dict):
        return False, {}
    return ancestry_proven(comparison, older), comparison


def workflow_id(api: GitHubAPI, path: str) -> int:
    workflow = api.get(f"/actions/workflows/{path}")
    workflow_id_value = workflow.get("id") if isinstance(workflow, dict) else None
    if not isinstance(workflow_id_value, int):
        raise ForkSyncError(f"Could not verify workflow identity for {path}.")
    return workflow_id_value


def request_runs(api: GitHubAPI) -> list[dict]:
    expected_id = workflow_id(api, FORK_WORKFLOW)
    runs = []
    for page in range(1, MAX_PAGES + 1):
        batch = api.get(
            f"/actions/workflows/{expected_id}/runs?event=workflow_dispatch&branch=main&per_page=100&page={page}"
        )
        if not isinstance(batch, dict) or not isinstance(
            batch.get("workflow_runs"), list
        ):
            raise ForkSyncError(
                "GitHub workflow-run inventory is malformed; hold unknown."
            )
        rows = batch["workflow_runs"]
        runs.extend(rows)
        if len(rows) < 100:
            break
    else:
        raise ForkSyncError(
            "Fork-sync request run inventory hit its page limit; hold unknown."
        )
    result = []
    for run in runs:
        if run.get("workflow_id") != expected_id:
            continue
        if run.get("actor", {}).get("login") != "github-actions[bot]":
            continue
        parsed = parse_request_run(run)
        if parsed is not None:
            result.append(parsed)
    return result


def active_workflow_runs(api: GitHubAPI, workflow_path: str) -> list[dict]:
    expected_id = workflow_id(api, workflow_path)
    runs = []
    for page in range(1, MAX_PAGES + 1):
        batch = api.get(
            f"/actions/workflows/{expected_id}/runs?branch=main&per_page=100&page={page}"
        )
        if not isinstance(batch, dict) or not isinstance(
            batch.get("workflow_runs"), list
        ):
            raise ForkSyncError("Workflow-run inventory is malformed; hold unknown.")
        rows = batch["workflow_runs"]
        runs.extend(
            run
            for run in rows
            if run.get("workflow_id") == expected_id
            and run.get("status") in {"queued", "in_progress", "waiting", "requested"}
        )
        if len(rows) < 100:
            return runs
    raise ForkSyncError("Workflow-run inventory hit its page limit; hold unknown.")


def adoption_run_for_target(api: GitHubAPI, target_sha: str) -> dict | None:
    """Return a native prior continuation for U; incomplete history is an error."""
    expected_id = workflow_id(api, ADOPTION_WORKFLOW)
    for page in range(1, MAX_PAGES + 1):
        batch = api.get(
            f"/actions/workflows/{expected_id}/runs?event=workflow_dispatch&branch=main&per_page=100&page={page}"
        )
        if not isinstance(batch, dict) or not isinstance(
            batch.get("workflow_runs"), list
        ):
            raise ForkSyncError(
                "Adoption workflow-run inventory is malformed; hold unknown."
            )
        rows = batch["workflow_runs"]
        for run in rows:
            match = ADOPTION_TITLE.fullmatch(run.get("display_title", ""))
            if (
                run.get("workflow_id") == expected_id
                and run.get("head_branch") == "main"
                and run.get("event") == "workflow_dispatch"
                and match is not None
                and match.group(1) == target_sha
            ):
                return run
        if len(rows) < 100:
            return None
    raise ForkSyncError(
        "Adoption workflow-run inventory hit its page limit; hold unknown."
    )


def exact_prs(api: GitHubAPI, state: str, target: str | None = None):
    if target is None:
        prs, complete = api.paginate(f"/pulls?state={state}&base=main")
    else:
        branch = f"sync-obi-upstream-{target}"
        prs, complete = api.paginate(
            f"/pulls?state={state}&base=main&head=grafana:{branch}", max_pages=2
        )
    if not complete:
        raise ForkSyncError(
            f"{state} fork PR inventory hit its page limit; hold unknown."
        )
    managed = []
    for pr in prs:
        branch = pr.get("head", {}).get("ref", "")
        marker = parse_pr_marker(pr)
        # Preserve malformed/retargeted managed identities as conflicts. Filtering
        # them out would allow another writer to open a second active sync PR.
        managed_prefix_match = branch.startswith("sync-obi-upstream-")
        exact_branch_match = (
            target is not None and branch == f"sync-obi-upstream-{target}"
        )
        if (target is None and managed_prefix_match) or exact_branch_match:
            managed.append(pr)
        elif marker is not None and (target is None or marker["target_sha"] == target):
            managed.append(pr)
    return managed


def merged_managed_pr_candidates(api: GitHubAPI) -> tuple[list[dict], bool]:
    """Use search only to discover candidates; every candidate is re-read and ancestry-checked."""
    query = urlencode(
        {
            "q": f'repo:{FORK_REPO} is:pr is:merged "Sync OBI fork to"',
            "per_page": 100,
            "page": 1,
        }
    )
    response = api.get(f"https://api.github.com/search/issues?{query}")
    if (
        not isinstance(response, dict)
        or not isinstance(response.get("items"), list)
        or response.get("incomplete_results") is not False
    ):
        raise ForkSyncError(
            "Merged managed fork-PR search is unavailable; hold unknown."
        )
    total = response.get("total_count")
    if not isinstance(total, int) or total > 1000:
        return [], False
    items = list(response["items"])
    pages = (total + 99) // 100
    for page in range(2, min(pages, 10) + 1):
        query = urlencode(
            {
                "q": f'repo:{FORK_REPO} is:pr is:merged "Sync OBI fork to"',
                "per_page": 100,
                "page": page,
            }
        )
        result = api.get(f"https://api.github.com/search/issues?{query}")
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("items"), list)
            or result.get("incomplete_results") is not False
            or result.get("total_count") != total
        ):
            raise ForkSyncError("Merged managed fork-PR search page is incomplete.")
        items.extend(result["items"])
    if len(items) != total or len({item.get("number") for item in items}) != total:
        raise ForkSyncError(
            "Merged managed fork-PR search returned incomplete or duplicate pages."
        )
    candidates = []
    for item in items:
        number = item.get("number")
        if not isinstance(number, int):
            continue
        pr = api.get(f"/pulls/{number}")
        if (
            isinstance(pr, dict)
            and parse_pr_marker(pr) is not None
            and pr.get("merged_at")
        ):
            candidates.append(pr)
    return candidates, True


def trusted_managed_base(
    fork_api: GitHubAPI,
    source_api: GitHubAPI,
    merge_base_sha: str | None,
    fork_main_sha: str,
    merged_prs: list[dict],
) -> bool:
    """Allow recurring divergence only when it is the parent of a verified prior sync PR."""
    if not valid_sha(merge_base_sha):
        return False
    source_main = sha_of(source_api, "/commits/main")
    on_upstream, _ = relation(source_api, merge_base_sha, source_main)
    if not on_upstream:
        return False
    for pr in merged_prs:
        marker = parse_pr_marker(pr)
        if (
            marker is None
            or marker["target_sha"] != merge_base_sha
            or not pr.get("merged_at")
        ):
            continue
        merge_sha = pr.get("merge_commit_sha", "")
        base_in_merge, _ = relation(fork_api, merge_base_sha, merge_sha)
        merge_in_main, _ = relation(fork_api, merge_sha, fork_main_sha)
        if base_in_merge and merge_in_main:
            return True
    return False


def status_comments(api: GitHubAPI, pr_number: int):
    comments, complete = api.paginate(f"/issues/{pr_number}/comments")
    if not complete:
        raise ForkSyncError("Status-comment inventory is incomplete.")
    return [c for c in comments if (c.get("body") or "").startswith(STATUS_MARKER)]


def fork_status_state(pr: dict, requests: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "pr_number": pr["number"],
        "target_sha": parse_pr_marker(pr)["target_sha"],
        "base_sha": parse_pr_marker(pr)["base_sha"],
        "stage": "awaiting-human-merge",
        "continuations": [],
        "request_run_ids": sorted({r["origin_run_id"] for r in requests}),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def reserve_for_target(api: GitHubAPI, pr: dict, target: str, requests: list[dict]):
    comments = status_comments(api, pr["number"])
    if len(comments) != 1:
        raise ForkSyncError(
            "A unique bot-owned fork status comment is required before continuation."
        )
    comment = comments[0]
    if (
        comment.get("user", {}).get("id") != BOT_ID
        or comment.get("user", {}).get("login") != BOT_LOGIN
    ):
        raise ForkSyncError(
            "Status comment is not authored by this trusted GitHub App."
        )
    state = parse_status_comment(comment.get("body") or "")
    if state.get("pr_number") != pr["number"]:
        raise ForkSyncError("Status comment PR identity does not match the merged PR.")
    request_ids = sorted({r["origin_run_id"] for r in requests})
    updated, action = reserve_continuation(state, target, request_ids)
    return comment, updated, action


def origin_is_trusted(api: GitHubAPI, request: dict) -> bool:
    origin = api.get(f"/actions/runs/{request['origin_run_id']}")
    expected_workflow = workflow_id(api, ADOPTION_WORKFLOW)
    return bool(
        isinstance(origin, dict)
        and origin.get("id") == int(request["origin_run_id"])
        and origin.get("workflow_id") == expected_workflow
        and origin.get("head_branch") == "main"
        and origin.get("event") in {"schedule", "workflow_dispatch"}
    )


def collect_snapshot(target_sha: str | None = None) -> dict:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise ForkSyncError("GH_TOKEN is required for read-only source discovery.")
    source_api = GitHubAPI(token, "open-telemetry/opentelemetry-ebpf-instrumentation")
    fork_api = GitHubAPI(token, FORK_REPO)
    upstream_main = sha_of(source_api, "/commits/main")
    target = target_sha or upstream_main
    if not valid_sha(target):
        raise ForkSyncError("Selected OBI source must be a full commit SHA.")
    target_on_upstream, _ = relation(source_api, target, upstream_main)
    if not target_on_upstream:
        raise ForkSyncError(
            "Selected OBI SHA is not proven reachable from upstream main."
        )
    fork_main = sha_of(fork_api, "/commits/main")
    exact_commit = fork_api.get(f"/commits/{target}")
    object_visible = (
        isinstance(exact_commit, dict) and exact_commit.get("sha") == target
    )
    contains_target, target_comparison = relation(fork_api, target, fork_main)
    ahead = fork_api.get(f"/compare/{fork_main}...{target}")
    compare_status = ahead.get("status") if isinstance(ahead, dict) else None
    merge_base_sha = (
        ahead.get("merge_base_commit", {}).get("sha")
        if isinstance(ahead, dict)
        else None
    )
    managed_merge_base = False
    if compare_status == "diverged":
        prior_prs, complete = merged_managed_pr_candidates(fork_api)
        if not complete:
            raise ForkSyncError(
                "Managed sync history is incomplete; recurring divergence is unknown."
            )
        managed_merge_base = trusted_managed_base(
            fork_api,
            source_api,
            merge_base_sha,
            fork_main,
            prior_prs,
        )
    open_prs = exact_prs(fork_api, "open")
    closed_prs = exact_prs(fork_api, "closed", target)
    branch = f"sync-obi-upstream-{target}"
    branch_ref, ref_status = fork_api.request("GET", f"/git/ref/heads/{branch}")
    branch_exists = ref_status == 200 and isinstance(branch_ref, dict)
    action = choose_sync_action(
        target_sha=target,
        fork_main_sha=fork_main,
        object_visible=object_visible,
        target_is_ancestor=contains_target,
        compare_status=compare_status,
        merge_base_sha=merge_base_sha,
        managed_merge_base=managed_merge_base,
        managed_open=open_prs,
        exact_closed=closed_prs,
        branch_exists=branch_exists,
    )
    return {
        **action,
        "target_sha": target,
        "upstream_main_sha": upstream_main,
        "fork_main_sha": fork_main,
        "target_is_ancestor": contains_target,
        "target_comparison": target_comparison,
        "merge_base_sha": merge_base_sha,
        "branch": branch,
        "exact_commit_verified": bool(
            exact_commit
            and exact_commit.get("commit", {}).get("verification", {}).get("verified")
            is True
        ),
        "open_prs": open_prs,
        "closed_prs": closed_prs,
    }


def create_request():
    token = os.environ.get("GH_TOKEN", "")
    target = os.environ.get("OBI_SHA", "")
    origin_id = os.environ.get("REQUEST_RUN_ID", "")
    if not token or not valid_sha(target) or not origin_id.isdigit():
        raise ForkSyncError(
            "Fork request needs GH_TOKEN, exact OBI_SHA, and REQUEST_RUN_ID."
        )
    if os.environ.get("GITHUB_REF") != "refs/heads/main":
        raise ForkSyncError(
            "Fork requests may only be dispatched from trusted default branch."
        )
    api = GitHubAPI(token, BEYLA_REPO)
    origin = api.get(f"/actions/runs/{origin_id}")
    if not isinstance(origin, dict) or origin.get("head_branch") != "main":
        raise ForkSyncError(
            "Originating adoption run is not a trusted default-branch run."
        )
    if origin.get("workflow_id") != workflow_id(api, ADOPTION_WORKFLOW):
        raise ForkSyncError("Originating run is not the OBI adoption workflow.")
    if origin.get("event") not in {"schedule", "workflow_dispatch"}:
        raise ForkSyncError("Originating adoption event is not trusted.")
    existing = request_runs(api)
    same_origin = [r for r in existing if r["origin_run_id"] == origin_id]
    if same_origin:
        targets = {r["target_sha"] for r in same_origin}
        if targets != {target}:
            raise ForkSyncError(
                "Originating run ID already has a conflicting exact target; hold."
            )
        output(
            {
                "action": "already-requested",
                "target_sha": target,
                "reason": "Exact request run exists.",
            }
        )
        return
    # The request run itself is an inexpensive durable event, not a branch or PR write.
    result, status = api.request(
        "POST",
        f"/actions/workflows/{FORK_WORKFLOW}/dispatches",
        {
            "ref": "main",
            "return_run_details": True,
            "inputs": {"obi_sha": target, "request_run_id": origin_id},
        },
    )
    run_id = result.get("workflow_run_id") if isinstance(result, dict) else None
    if status != 200 or not isinstance(run_id, int):
        raise ForkSyncError(
            "Fork request dispatch returned no verified run identity; do not retry automatically."
        )
    dispatched = api.get(f"/actions/runs/{run_id}")
    if (
        not isinstance(dispatched, dict)
        or dispatched.get("workflow_id") != workflow_id(api, FORK_WORKFLOW)
        or dispatched.get("event") != "workflow_dispatch"
        or dispatched.get("head_branch") != "main"
        or dispatched.get("display_title") != request_title(target, origin_id)
    ):
        raise ForkSyncError(
            "Dispatched fork request identity is ambiguous; do not retry automatically."
        )
    output(
        {
            "action": "requested",
            "target_sha": target,
            "reason": "Exact target request dispatched.",
        }
    )


def publish_candidate():
    if os.environ.get("OBI_FORK_SYNC_WRITER_ENABLED") != "true":
        raise ForkSyncError(
            "OBI_FORK_SYNC_WRITER_ENABLED is not true; no fork ref or PR was written."
        )
    expected_base = os.environ.get("EXPECTED_FORK_BASE", "")
    target = os.environ.get("OBI_SHA", "")
    if not valid_sha(expected_base) or not valid_sha(target):
        raise ForkSyncError(
            "Create-only publisher needs exact fork base and source SHA."
        )
    token = os.environ.get("APP_TOKEN", "")
    if not token:
        raise ForkSyncError("APP_TOKEN is required for the fork publisher.")
    snapshot = collect_snapshot(target)
    if (
        snapshot.get("action") != "create"
        or snapshot.get("fork_main_sha") != expected_base
    ):
        raise ForkSyncError(
            snapshot.get("reason", "Source/fork state changed; no PR was created.")
        )
    if snapshot.get("exact_commit_verified") is not True:
        raise ForkSyncError(
            "Exact source commit lacks a verified signature; no ref was created."
        )
    api = GitHubAPI(token, FORK_REPO)
    branch = snapshot["branch"]
    request_id = os.environ.get("REQUEST_RUN_ID", "")
    if request_id:
        beyla_api = GitHubAPI(os.environ.get("GH_TOKEN", ""), BEYLA_REPO)
        current_run_id = os.environ.get("GITHUB_RUN_ID", "")
        current_run = (
            beyla_api.get(f"/actions/runs/{current_run_id}")
            if current_run_id.isdigit()
            else None
        )
        if (
            not isinstance(current_run, dict)
            or current_run.get("workflow_id") != workflow_id(beyla_api, FORK_WORKFLOW)
            or current_run.get("event") != "workflow_dispatch"
            or current_run.get("head_branch") != "main"
            or current_run.get("actor", {}).get("login") != "github-actions[bot]"
            or current_run.get("display_title") != request_title(target, request_id)
            or not origin_is_trusted(beyla_api, {"origin_run_id": request_id})
        ):
            raise ForkSyncError(
                "Request run is not the trusted exact-SHA daily adoption dispatch."
            )
    # This is the only code ref write: a new exact-U topic ref, never main or an existing branch.
    _, status = api.request(
        "POST",
        "/git/refs",
        {"ref": f"refs/heads/{branch}", "sha": target},
    )
    if status != 201:
        raise ForkSyncError(
            "Exact topic ref creation was not confirmed; do not update or force-push it."
        )
    current_fork_main = sha_of(api, "/commits/main")
    if current_fork_main != expected_base:
        raise ForkSyncError(
            "Fork main moved after ref creation; leave the branch untouched and hold."
        )
    # A newer upstream head does not change the selected SHA; confirm U remains canonical.
    current_upstream = sha_of(
        GitHubAPI(token, "open-telemetry/opentelemetry-ebpf-instrumentation"),
        "/commits/main",
    )
    still_canonical, _ = relation(
        GitHubAPI(token, "open-telemetry/opentelemetry-ebpf-instrumentation"),
        target,
        current_upstream,
    )
    if not still_canonical:
        raise ForkSyncError(
            "Selected SHA is no longer on upstream main; leave the exact branch and hold."
        )
    marker = f"<!-- grafana-obi-fork-sync:v1 target={target} base={expected_base} -->"
    body = (
        f"{marker}\nThis draft proposes the exact OBI commit `{target}` on top of fork main `{expected_base}`.\n\n"
        "Please merge using a **merge commit**. Squash or rebase rewrites the selected OBI ancestry, "
        "so automatic Beyla adoption will remain blocked until the exact source commit is proven reachable. "
        "This PR does not change fork main automatically; human review and merge are required."
    )
    pr, status = api.request(
        "POST",
        "/pulls",
        {
            "title": f"Sync OBI fork to {target[:12]}",
            "head": branch,
            "base": "main",
            "body": body,
            "draft": True,
        },
    )
    if status != 201 or not isinstance(pr, dict) or pr.get("draft") is not True:
        raise ForkSyncError(
            "Draft fork PR creation was not confirmed; inspect the exact managed branch before retry."
        )
    if (
        pr.get("user", {}).get("id") != BOT_ID
        or pr.get("user", {}).get("login") != BOT_LOGIN
    ):
        raise ForkSyncError(
            "Fork PR author is not the expected GitHub App; do not continue automatically."
        )
    # Create status exactly once with the new PR. Existing PRs missing it are never silently repaired.
    origin_ids = [os.environ.get("REQUEST_RUN_ID", "")]
    origin_ids = [value for value in origin_ids if value.isdigit()]
    state = fork_status_state(pr, [{"origin_run_id": value} for value in origin_ids])
    state["message"] = (
        "Human review and merge commit are required before exact-SHA adoption can continue."
    )
    comment, comment_status = api.request(
        "POST",
        f"/issues/{pr['number']}/comments",
        {"body": render_status_comment(state)},
    )
    if (
        comment_status != 201
        or not isinstance(comment, dict)
        or comment.get("user", {}).get("id") != BOT_ID
        or comment.get("user", {}).get("login") != BOT_LOGIN
    ):
        raise ForkSyncError(
            "PR exists but status-comment creation was ambiguous; hold for human reconciliation."
        )
    output(
        {
            "action": "created",
            "target_sha": target,
            "fork_main_sha": expected_base,
            "pr_number": pr["number"],
            "reason": "Draft exact-SHA fork PR created; merge remains human-only.",
        }
    )


def poll_continuations():
    """Reserve once per target, then dispatch the existing exact-SHA adoption workflow."""
    token = os.environ.get("APP_TOKEN", "")
    dispatch_token = os.environ.get("GITHUB_TOKEN", "")
    if not token or not dispatch_token:
        raise ForkSyncError(
            "Both App and repository workflow-dispatch tokens are required."
        )
    fork = GitHubAPI(token, FORK_REPO)
    beyla_read = GitHubAPI(dispatch_token, BEYLA_REPO)
    all_requests = request_runs(beyla_read)
    selected = select_requests(
        [
            {
                "display_title": request_title(r["target_sha"], r["origin_run_id"]),
                "event": "workflow_dispatch",
                "head_branch": "main",
                "id": int(r["run_id"]),
                "created_at": r["created_at"],
                "status": r["status"],
                "conclusion": r["conclusion"],
            }
            for r in all_requests
        ]
    )
    if selected["conflicts"]:
        output(
            {
                "action": "hold",
                "reason": "One origin run ID has conflicting exact OBI target requests.",
            }
        )
        return
    requests = [
        request
        for request in selected["requests"]
        if all(
            origin_is_trusted(beyla_read, {**request, "origin_run_id": origin})
            for origin in request["origin_run_ids"]
        )
    ]
    if active_workflow_runs(beyla_read, ADOPTION_WORKFLOW):
        output(
            {
                "action": "defer",
                "reason": "A trusted main OBI adoption workflow is already active.",
            }
        )
        return
    upstream_api = GitHubAPI(token, "open-telemetry/opentelemetry-ebpf-instrumentation")
    fork_main_sha = sha_of(fork, "/commits/main")
    upstream_main_sha = sha_of(upstream_api, "/commits/main")
    merged_prs, search_complete = merged_managed_pr_candidates(fork)
    if not search_complete:
        raise ForkSyncError(
            "Merged managed fork-PR search is incomplete; hold unknown."
        )
    open_beyla_prs, complete = beyla_read.paginate("/pulls?state=open&base=main")
    if not complete:
        raise ForkSyncError(
            "Beyla active-PR inventory is incomplete; hold continuation."
        )
    for open_pr in open_beyla_prs:
        managed_adoption = bool(ADOPTION_MARKER.search(open_pr.get("body") or ""))
        if not managed_adoption and not str(
            open_pr.get("head", {}).get("ref", "")
        ).startswith("update-obi-adoption-"):
            files, complete = beyla_read.paginate(
                f"/pulls/{open_pr['number']}/files", max_pages=2
            )
            if not complete:
                output(
                    {
                        "action": "defer",
                        "reason": "An open Beyla PR file inventory is incomplete.",
                    }
                )
                return
            managed_adoption = any(file.get("filename") == ".obi-src" for file in files)
        if managed_adoption:
            output(
                {
                    "action": "defer",
                    "reason": "An open Beyla PR changes the OBI pin; preserve the single-writer state.",
                }
            )
            return
    for request in requests:
        target = request["target_sha"]
        still_upstream, _ = relation(upstream_api, target, upstream_main_sha)
        in_fork, _ = relation(fork, target, fork_main_sha)
        if not still_upstream or not in_fork:
            continue
        pin_data = beyla_read.get("/contents/.obi-src?ref=main")
        pin_sha = pin_data.get("sha") if isinstance(pin_data, dict) else None
        pin_contains, _ = (
            relation(fork, target, pin_sha) if valid_sha(pin_sha) else (False, {})
        )
        if pin_contains:
            output(
                {
                    "action": "adopted",
                    "target_sha": target,
                    "reason": "The exact source is already on Beyla main.",
                }
            )
            continue
        verified_merges = []
        for pr in merged_prs:
            marker = parse_pr_marker(pr)
            if marker is None or not pr.get("merged_at"):
                continue
            head_sha = pr.get("head", {}).get("sha", "")
            merge_sha = pr.get("merge_commit_sha", "")
            target_in_head, target_comparison = relation(fork, target, head_sha)
            target_in_merge, merge_comparison = relation(fork, target, merge_sha)
            head_in_merge, head_comparison = relation(fork, head_sha, merge_sha)
            merge_in_main, fork_comparison = relation(fork, merge_sha, fork_main_sha)
            if target_in_head and target_in_merge and head_in_merge and merge_in_main:
                verified_merges.append(
                    {
                        **pr,
                        "pr_target_sha": marker["target_sha"],
                        "target_comparison": target_comparison,
                        "merge_comparison": merge_comparison,
                        "head_comparison": head_comparison,
                        "fork_comparison": fork_comparison,
                    }
                )
        if not verified_merges:
            continue
        exact_fork_target_prs = exact_prs(fork, "closed", target)
        if any(
            pr.get("state") == "closed" and not pr.get("merged_at")
            for pr in exact_fork_target_prs
        ):
            continue
        adoption_branch = f"update-obi-adoption-{target}"
        closed_adoption, complete = beyla_read.paginate(
            f"/pulls?state=closed&base=main&head=grafana:{adoption_branch}", max_pages=2
        )
        if not complete:
            continue
        if any(
            pr.get("state") == "closed"
            and not pr.get("merged_at")
            and f"target={target}" in (pr.get("body") or "")
            for pr in closed_adoption
        ):
            continue
        # A target may be contained by several later merged sync PRs. Scan every
        # proven candidate before reserving so an older reservation is global.
        existing_reservations = []
        for candidate in verified_merges:
            comments = status_comments(fork, candidate["number"])
            if len(comments) != 1:
                raise ForkSyncError(
                    "A containing managed PR lacks one unique status comment; hold."
                )
            candidate_comment = comments[0]
            if (
                candidate_comment.get("user", {}).get("id") != BOT_ID
                or candidate_comment.get("user", {}).get("login") != BOT_LOGIN
            ):
                raise ForkSyncError(
                    "A containing PR status comment is not from the verified App; hold."
                )
            candidate_state = parse_status_comment(candidate_comment.get("body") or "")
            if any(
                row.get("target_sha") == target
                for row in candidate_state["continuations"]
            ):
                existing_reservations.append(
                    (candidate, candidate_comment, candidate_state)
                )
        if len(existing_reservations) > 1:
            raise ForkSyncError(
                "This target has multiple continuation reservations; hold for reconciliation."
            )
        if existing_reservations:
            candidate, comment, state = existing_reservations[0]
            record = next(
                row for row in state["continuations"] if row.get("target_sha") == target
            )
            run_id = record.get("dispatch_run_id")
            if record.get("stage") == "reserved" or record.get("stage") == "ambiguous":
                continue
            if run_id is None:
                continue
            run = beyla_read.get(f"/actions/runs/{run_id}")
            if not isinstance(run, dict) or run.get("workflow_id") != workflow_id(
                beyla_read, ADOPTION_WORKFLOW
            ):
                continue
            if run.get("status") != "completed":
                continue
            pin_data = beyla_read.get("/contents/.obi-src?ref=main")
            pin_sha = pin_data.get("sha") if isinstance(pin_data, dict) else None
            pin_contains, _ = (
                relation(fork, target, pin_sha) if valid_sha(pin_sha) else (False, {})
            )
            adoption_prs, adoption_complete = beyla_read.paginate(
                "/pulls?state=open&base=main"
            )
            if not adoption_complete:
                continue
            matching_adoption = [
                pr
                for pr in adoption_prs
                if f"target={target}" in (pr.get("body") or "")
                and pr.get("head", {}).get("ref") == f"update-obi-adoption-{target}"
            ]
            if pin_contains:
                new_state = update_continuation(
                    state, target, "adopted", "Exact target is now on Beyla main."
                )
            elif len(matching_adoption) == 1:
                new_state = update_continuation(
                    state,
                    target,
                    "awaiting-beyla-human-merge",
                    f"Beyla PR #{matching_adoption[0]['number']} is open.",
                )
            else:
                new_state = update_continuation(
                    state,
                    target,
                    "blocked",
                    "The one authorized adoption workflow run completed without a verified target PR or main pin; human recovery required.",
                )
            response, status = fork.request(
                "PATCH",
                f"/issues/comments/{comment['id']}",
                {"body": render_status_comment(new_state)},
            )
            if status != 200 or not isinstance(response, dict):
                raise ForkSyncError(
                    "Could not persist terminal continuation status; hold."
                )
            output(
                {
                    "action": new_state["continuations"][-1]["stage"],
                    "target_sha": target,
                    "reason": "Existing continuation was inspected; no dispatch was repeated.",
                }
            )
            continue
        prior_run = adoption_run_for_target(beyla_read, target)
        if prior_run is not None:
            output(
                {
                    "action": "hold",
                    "target_sha": target,
                    "reason": "A native adoption workflow run already exists for this exact target; do not dispatch again.",
                }
            )
            continue
        # Prefer the newest trusted merged PR containing U; older PRs remain
        # searchable and cannot eclipse an existing reservation.
        verified_merges.sort(key=lambda row: row.get("merged_at") or "", reverse=True)
        verified_merge = verified_merges[0]
        comments = status_comments(fork, verified_merge["number"])
        if len(comments) != 1:
            continue
        comment = comments[0]
        if (
            comment.get("user", {}).get("id") != BOT_ID
            or comment.get("user", {}).get("login") != BOT_LOGIN
        ):
            continue
        state = parse_status_comment(comment.get("body") or "")
        reservation, action = reserve_continuation(
            state, target, request.get("origin_run_ids", [request["origin_run_id"]])
        )
        if action == "already-reserved":
            continue
        expected_comment_body = comment.get("body")
        updated = render_status_comment(reservation)
        # Re-read the PR/comment just before the reservation CAS-like update.
        latest_pr = fork.get(f"/pulls/{verified_merge['number']}")
        latest_comments = status_comments(fork, verified_merge["number"])
        if (
            not isinstance(latest_pr, dict)
            or len(latest_comments) != 1
            or latest_comments[0].get("id") != comment.get("id")
        ):
            raise ForkSyncError(
                "Fork PR/status identity changed before continuation reservation."
            )
        latest_marker = parse_pr_marker(latest_pr)
        current_fork_main = sha_of(fork, "/commits/main")
        current_upstream_main = sha_of(upstream_api, "/commits/main")
        target_still_upstream, _ = relation(upstream_api, target, current_upstream_main)
        target_in_current_fork, _ = relation(fork, target, current_fork_main)
        merge_in_current_fork, _ = relation(
            fork, verified_merge["merge_commit_sha"], current_fork_main
        )
        if (
            latest_pr.get("state") != "closed"
            or not latest_pr.get("merged_at")
            or latest_marker is None
            or latest_marker["target_sha"] != verified_merge["pr_target_sha"]
            or latest_pr.get("merge_commit_sha") != verified_merge["merge_commit_sha"]
            or not target_still_upstream
            or not target_in_current_fork
            or not merge_in_current_fork
        ):
            raise ForkSyncError(
                "Merged-PR/source ancestry changed before continuation reservation."
            )
        if latest_comments[0].get("body") != expected_comment_body:
            raise ForkSyncError("Fork status changed concurrently; do not dispatch.")
        response, patch_status = fork.request(
            "PATCH", f"/issues/comments/{comment['id']}", {"body": updated}
        )
        if (
            patch_status != 200
            or not isinstance(response, dict)
            or response.get("body") != updated
        ):
            raise ForkSyncError(
                "Continuation reservation was not verified; do not dispatch."
            )
        # Use the repository's GITHUB_TOKEN only for workflow_dispatch.
        dispatch = GitHubAPI(dispatch_token, BEYLA_REPO)
        result, status = dispatch.request(
            "POST",
            f"/actions/workflows/{ADOPTION_WORKFLOW}/dispatches",
            {
                "ref": "main",
                "return_run_details": True,
                "inputs": {
                    "obi_sha": target,
                    "request_run_id": request["origin_run_id"],
                },
            },
        )
        if (
            status != 200
            or not isinstance(result, dict)
            or not isinstance(result.get("workflow_run_id"), int)
        ):
            raise ForkSyncError(
                "Adoption dispatch is ambiguous; reservation remains and will not be retried."
            )
        dispatched = dispatch.get(f"/actions/runs/{result['workflow_run_id']}")
        if (
            not isinstance(dispatched, dict)
            or dispatched.get("workflow_id") != workflow_id(dispatch, ADOPTION_WORKFLOW)
            or dispatched.get("event") != "workflow_dispatch"
            or dispatched.get("head_branch") != "main"
            or dispatched.get("display_title")
            != adoption_title(target, request["origin_run_id"])
        ):
            raise ForkSyncError(
                "Adoption dispatch identity is ambiguous; reservation will not be retried."
            )
        final_state = set_dispatch_result(
            reservation, target, result["workflow_run_id"]
        )
        # The lock is short-lived: only revalidation, reservation, and dispatch happen here.
        fork.request(
            "PATCH",
            f"/issues/comments/{comment['id']}",
            {"body": render_status_comment(final_state)},
        )
        output(
            {
                "action": "dispatched",
                "target_sha": target,
                "pr_number": verified_merge["number"],
                "reason": "Exact target is in an approved merge commit; existing adoption workflow was dispatched once.",
            }
        )
        return
    output(
        {
            "action": "hold",
            "reason": "No pending exact target has a verified merged fork PR containing it.",
        }
    )


def output(values: dict):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        lines = ["# OBI fork-sync preflight", ""]
        for key in ("action", "reason", "target_sha", "fork_main_sha", "pr_number"):
            if values.get(key) is not None:
                lines.append(f"- **{key.replace('_', ' ')}:** `{values[key]}`")
        Path(summary_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as stream:
            for key in (
                "action",
                "reason",
                "target_sha",
                "fork_main_sha",
                "branch",
                "pr_number",
            ):
                value = values.get(key)
                if value is not None:
                    stream.write(f"{key}={value}\n")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {
        "request",
        "inspect",
        "publish",
        "continue",
    }:
        raise ForkSyncError(
            "Usage: obi_fork_sync.py {request|inspect|publish|continue}"
        )
    command = sys.argv[1]
    if command == "request":
        create_request()
        return
    if command == "inspect":
        target = os.environ.get("OBI_SHA") or None
        snapshot = collect_snapshot(target)
        output(snapshot)
        return
    if command == "publish":
        publish_candidate()
        return
    if command == "continue":
        poll_continuations()


if __name__ == "__main__":
    try:
        main()
    except ForkSyncError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
