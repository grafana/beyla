"""Collect read-only exact-SHA source facts and print JSON plus an Actions summary."""

import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from plan import publish_plan
from reconcile import SHA, parse_time, reconcile

REPO = "grafana/beyla"
UPSTREAM = "https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation.git"


def cmd(args, timeout=30):
    return subprocess.run(
        args, text=True, capture_output=True, check=True, timeout=timeout
    ).stdout.strip()


def is_ancestor(repo, older, newer):
    result = subprocess.run(
        ["git", "-C", repo, "merge-base", "--is-ancestor", older, newer],
        check=False,
        timeout=30,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("Could not evaluate commit ancestry.")
    return result.returncode == 0


def api(endpoint):
    # Single bounded page only. Callers track whether the page limit may truncate results.
    return json.loads(cmd(["gh", "api", endpoint]))


def search_issues(query):
    raw = cmd(
        [
            "gh",
            "api",
            "--method",
            "GET",
            "search/issues",
            "-f",
            f"q={query}",
            "-f",
            "per_page=100",
        ]
    )
    return json.loads(raw)


def inspect_closed_target_history(facts, upstream):
    """Check the exact managed branch plus bounded legacy SHA matches."""
    matches = {}
    complete = True
    managed_branch = f"update-obi-adoption-{upstream}"
    managed = api(
        f"repos/{REPO}/pulls?state=all&head=grafana:{managed_branch}&base=main&per_page=100&page=1"
    )
    if not isinstance(managed, list) or len(managed) >= 100:
        complete = False
        managed = []
    for pr in managed:
        if pr.get("state") != "closed":
            continue
        if pr.get("changed_files", 0) > 100:
            complete = False
            continue
        files = api(f"repos/{REPO}/pulls/{pr['number']}/files?per_page=100&page=1")
        if not isinstance(files, list) or len(files) >= 100:
            complete = False
            continue
        if not any(file.get("filename") == ".obi-src" for file in files):
            continue
        target = target_for(pr)
        marker = f"<!-- grafana-beyla-obi-adoption:v1 target={upstream} base="
        if target != upstream or marker not in (pr.get("body") or ""):
            complete = False
            continue
        facts["closed_exact_target"] = True
        if not pr.get("merged_at"):
            facts["rejected_exact_target"] = True
    for term in {upstream, upstream[:7]}:
        result = search_issues(f"repo:{REPO} is:pr is:closed {term}")
        items = result.get("items", [])
        if (
            not isinstance(items, list)
            or result.get("total_count", 0) > 100
            or result.get("incomplete_results") is True
        ):
            complete = False
            continue
        matches.update(
            {
                item["number"]: item
                for item in items
                if isinstance(item.get("number"), int)
            }
        )
        if len(matches) > 50:
            complete = False
            break
    for number in sorted(matches)[:50]:
        pr = api(f"repos/{REPO}/pulls/{number}")
        if pr.get("changed_files", 0) > 100:
            complete = False
            continue
        files = api(f"repos/{REPO}/pulls/{number}/files?per_page=100&page=1")
        if len(files) >= 100:
            complete = False
        if not any(file.get("filename") == ".obi-src" for file in files):
            continue
        target = target_for(pr)
        if not target:
            complete = False
            continue
        if target == upstream:
            facts["closed_exact_target"] = True
            if not pr.get("merged_at"):
                facts["rejected_exact_target"] = True
    facts["closed_target_history_complete"] = complete


def _collect_open_pr_inventory(facts):
    open_prs = api(f"repos/{REPO}/pulls?state=open&base=main&per_page=100&page=1")
    open_complete = len(open_prs) < 100
    for pr in open_prs:
        if pr.get("changed_files", 0) > 100:
            open_complete = False
            continue
        files = api(f"repos/{REPO}/pulls/{pr['number']}/files?per_page=100&page=1")
        if len(files) >= 100:
            open_complete = False
        if not any(file.get("filename") == ".obi-src" for file in files):
            continue
        target = target_for(pr)
        if not target:
            raise RuntimeError(
                f"Could not resolve .obi-src target for PR #{pr['number']}."
            )
        body = pr.get("body") or ""
        match = re.search(
            r"<!-- grafana-beyla-obi-adoption:v1 target=([0-9a-f]{40}) base=([0-9a-f]{40}) -->",
            body,
        )
        entry = {
            "number": pr["number"],
            "url": pr["html_url"],
            "head_sha": pr["head"]["sha"],
            "head_branch": pr["head"]["ref"],
            "head_repo": pr["head"]["repo"]["full_name"],
            "target_sha": target,
            "draft": pr.get("draft"),
            "author": pr.get("user", {}).get("login"),
            "managed_marker": bool(match and match.group(1) == target),
            "managed_base_sha": match.group(2)
            if match and match.group(1) == target
            else None,
        }
        facts["active_prs"].append(entry)
    facts["open_pr_inventory_complete"] = open_complete


def _collect_pr_inventory(facts, upstream):
    _collect_open_pr_inventory(facts)
    inspect_closed_target_history(facts, upstream)


def collect_open_pr_inventory(facts):
    """Inspect live open PRs without the ancestry/closed-history work used for new candidates."""
    facts["open_pr_inventory_complete"] = False
    try:
        _collect_open_pr_inventory(facts)
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        OSError,
        RuntimeError,
    ):
        facts["open_pr_inventory_complete"] = False
        raise


def collect_pr_inventory(facts, upstream):
    """Collect bounded PR facts; any interruption invalidates partial inventory."""
    facts["open_pr_inventory_complete"] = False
    facts["closed_target_history_complete"] = False
    try:
        _collect_pr_inventory(facts, upstream)
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        OSError,
        RuntimeError,
    ):
        facts["open_pr_inventory_complete"] = False
        facts["closed_target_history_complete"] = False
        raise


def emit(report):
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    print(json.dumps(report, indent=2, sort_keys=True))
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        source, pending, adopt = report["source"], report["pending"], report["adoption"]
        Path(summary_path).write_text(
            "# OBI adoption preflight (read-only)\n\n"
            f"- Outcome: **{adopt['outcome']}**\n- Upstream: `{source['upstream_sha']}`\n- Current pin: `{source['pin_sha']}`\n"
            f"- Pending: {pending['count']} (age proxy: {pending['freshness']})\n"
            f"- Blocker: {adopt['blocker'] or 'none'}\n- Next action: {adopt['next_action']}\n\n"
            "A report is not publication or release authorization.\n"
        )
    output_path = os.getenv("GITHUB_OUTPUT")
    if output_path:
        source, adoption = report["source"], report["adoption"]
        outputs = {
            "report_json": encoded,
            "outcome": adoption["outcome"],
            "upstream_sha": source.get("upstream_sha") or "",
            "pin_sha": source.get("pin_sha") or "",
            "main_head_sha": source.get("main_head_sha") or "",
            "active_prs_json": json.dumps(
                adoption["active_prs"], separators=(",", ":")
            ),
            "open_pr_complete": str(report["inventory"]["open_pr_complete"]).lower(),
            "closed_target_history_complete": str(
                report["inventory"]["closed_target_history_complete"]
            ).lower(),
        }
        plan = publish_plan(report)
        outputs.update(
            {
                "publish_action": plan["action"],
                "publish_reason": plan["reason"],
                "target_sha": plan["target_sha"] or "",
                "base_sha": plan["base_sha"] or "",
                "branch": plan["branch"] or "",
                "pr_number": str(plan["pr_number"] or ""),
                "expected_pr_head": plan["expected_pr_head"] or "",
            }
        )
        with open(output_path, "a", encoding="utf-8") as output:
            for key, value in outputs.items():
                if "\n" in value or "\r" in value:
                    raise ValueError(f"Unsafe multiline workflow output: {key}")
                output.write(f"{key}={value}\n")


def target_for(pr):
    try:
        return json.loads(
            cmd(
                ["gh", "api", f"repos/{REPO}/contents/.obi-src?ref={pr['head']['sha']}"]
            )
        ).get("sha")
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        OSError,
    ):
        return None


def main():
    now = datetime.now(timezone.utc).isoformat()
    run_facts = {
        "run_id": os.getenv("GITHUB_RUN_ID"),
        "attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "ref": os.getenv("GITHUB_REF"),
        "head_sha": os.getenv("GITHUB_SHA"),
    }
    facts = {
        "run": run_facts,
        "source": {},
        "active_prs": [],
        "open_pr_inventory_complete": False,
        "closed_target_history_complete": False,
    }
    try:
        if run_facts["ref"] != "refs/heads/main" or not run_facts["head_sha"]:
            raise RuntimeError("Run must use trusted main ref.")
        row = cmd(["git", "ls-tree", run_facts["head_sha"], ".obi-src"]).split()
        if len(row) < 3 or row[1] != "commit":
            raise RuntimeError("Cannot read .obi-src gitlink at workflow SHA.")
        pin = row[2]
        selected = os.getenv("OBI_SHA", "").strip()
        if selected:
            if not SHA.fullmatch(selected):
                raise RuntimeError(
                    "Selected OBI SHA must be a lowercase 40-character commit."
                )
            upstream = selected
        else:
            sample = cmd(["git", "ls-remote", UPSTREAM, "refs/heads/main"]).split()
            if len(sample) != 2 or not SHA.fullmatch(sample[0]):
                raise RuntimeError("Could not sample one full upstream main SHA.")
            upstream = sample[0]
        current_main = cmd(["gh", "api", f"repos/{REPO}/commits/main", "--jq", ".sha"])
        if upstream == pin:
            facts["source"] = {
                "upstream_sha": upstream,
                "pin_sha": pin,
                "main_head_sha": current_main,
                "snapshot_current_main": current_main == run_facts["head_sha"],
                "pending_count": 0,
                "timestamps_valid": True,
            }
            collect_open_pr_inventory(facts)
            emit(reconcile(facts, now))
            return
        observed_at = parse_time(now)
        with tempfile.TemporaryDirectory() as tmp:
            repo = str(Path(tmp) / "repo.git")
            cmd(["git", "init", "--bare", repo])
            # Fetch moving refs, then verify their result still equals the single sampled SHA.
            cmd(
                [
                    "git",
                    "-C",
                    repo,
                    "fetch",
                    "--filter=blob:none",
                    "--no-tags",
                    UPSTREAM,
                    "+refs/heads/main:refs/remotes/upstream/main",
                ],
                timeout=180,
            )
            fetched = cmd(
                ["git", "-C", repo, "rev-parse", "refs/remotes/upstream/main"]
            )
            if not is_ancestor(repo, upstream, fetched):
                raise RuntimeError(
                    "Sampled upstream SHA is not reachable from the fetched upstream main."
                )
            # Pin object must be in the sampled ancestry; a missing object is unknown, not guessed.
            present = (
                subprocess.run(
                    ["git", "-C", repo, "cat-file", "-e", pin + "^{commit}"],
                    check=False,
                    timeout=30,
                ).returncode
                == 0
            )
            if not present:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        repo,
                        "fetch",
                        "--filter=blob:none",
                        "--no-tags",
                        UPSTREAM,
                        pin,
                    ],
                    check=False,
                    capture_output=True,
                    timeout=180,
                )
                present = (
                    subprocess.run(
                        ["git", "-C", repo, "cat-file", "-e", pin + "^{commit}"],
                        check=False,
                        timeout=30,
                    ).returncode
                    == 0
                )
            if not present:
                raise RuntimeError(
                    "Current pin object is unavailable in fetched graph."
                )
            if (
                cmd(["git", "-C", repo, "rev-parse", "--is-shallow-repository"])
                != "false"
            ):
                raise RuntimeError("Fetched graph is shallow.")
            ancestor = is_ancestor(repo, pin, upstream)
            upstream_ancestor_of_pin = is_ancestor(repo, upstream, pin)
            pending_result = subprocess.run(
                ["git", "-C", repo, "rev-list", upstream, "^" + pin],
                check=False,
                text=True,
                capture_output=True,
                timeout=30,
            )
            if pending_result.returncode != 0:
                raise RuntimeError(
                    "Could not enumerate complete pending commit ancestry."
                )
            pending = pending_result.stdout.splitlines()
            log = cmd(
                ["git", "-C", repo, "log", "--format=%cI%x09%H", upstream, "^" + pin],
                timeout=30,
            )
            parsed = []
            for line in log.splitlines():
                stamp, sha = line.split("\t", 1)
                parsed.append((parse_time(stamp), sha, stamp))
            if len(parsed) != len(pending):
                raise RuntimeError(
                    "Commit timestamp inventory does not match complete pending ancestry."
                )
            timestamps_valid = all(
                stamp is not None and stamp <= observed_at for stamp, _, _ in parsed
            )
            oldest = (
                min(parsed, key=lambda item: (item[0], item[1]))
                if parsed and timestamps_valid
                else (None, None, None)
            )
        facts["source"] = {
            "upstream_sha": upstream,
            "pin_sha": pin,
            "graph_complete": True,
            "snapshot_current_main": current_main == run_facts["head_sha"],
            "main_head_sha": current_main,
            "pin_is_ancestor": ancestor,
            "upstream_is_ancestor_of_pin": upstream_ancestor_of_pin,
            "pending_count": len(pending),
            "oldest_committer_at": oldest[2],
            "oldest_sha": oldest[1],
            "timestamps_valid": timestamps_valid,
        }
        collect_pr_inventory(facts, upstream)
    except (
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        OSError,
        RuntimeError,
    ) as exc:
        facts["open_pr_inventory_complete"] = False
        facts["closed_target_history_complete"] = False
        facts["collection_error"] = f"{type(exc).__name__}: {exc}"
    report = reconcile(facts, now)
    report["collection_error"] = facts.get("collection_error")
    emit(report)


if __name__ == "__main__":
    main()
