"""Build a bounded, read-only release reconciliation report from GitHub facts."""

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACTIVE = {"queued", "in_progress", "waiting", "requested", "pending"}
KNOWN = ACTIVE | {"completed"}
FAILURES = {"failure", "cancelled", "timed_out", "action_required"}


def _read(path, shape, unavailable):
    try:
        value = json.loads(Path(path).read_text())
        if shape == "object":
            if not isinstance(value, dict):
                raise ValueError("expected object")
            return value
        if not isinstance(value, list):
            # Schema-shape failures intentionally share the ValueError parse contract.
            raise ValueError("expected paginated array")  # noqa: TRY004
        rows = []
        for page in value:
            if shape == "runs":
                if not isinstance(page, dict) or not isinstance(
                    page.get("workflow_runs"), list
                ):
                    raise ValueError("expected workflow_runs page")
                rows.extend(page["workflow_runs"])
            else:
                if not isinstance(page, list):
                    raise ValueError("expected array page")
                rows.extend(page)
        return rows
    except (OSError, ValueError, json.JSONDecodeError):
        unavailable.append(Path(path).name)
        return {} if shape == "object" else []


def load_facts(directory, repository):
    """Read API response files; failed/schema-invalid responses become unknown facts."""
    base = Path(directory)
    unavailable = []
    candidate = _read(base / "candidate.json", "object", unavailable)
    obi = _read(base / "obi.json", "object", unavailable)
    runs = _read(base / "prepare-runs.json", "runs", unavailable) + _read(
        base / "tag-runs.json", "runs", unavailable
    )
    releases = _read(base / "releases.json", "array", unavailable)
    beyla_refs = _read(base / "beyla-refs.json", "array", unavailable)

    def refs(rows, label):
        if not all(
            isinstance(row, dict) and isinstance(row.get("ref"), str) for row in rows
        ):
            unavailable.append("malformed " + label)
            return []
        return [row["ref"].removeprefix("refs/heads/") for row in rows]

    return {
        "repository": repository,
        "candidate": {"sha": candidate.get("sha"), "obi_sha": obi.get("sha")},
        "runs": runs,
        "releases": releases,
        "beyla_refs": refs(beyla_refs, "Beyla refs"),
        "unavailable": unavailable,
    }


def _utc_datetime(value):
    if not isinstance(value, str):
        # Invalid timestamp values intentionally use the ValueError parse contract.
        raise ValueError("timestamp must be a string")  # noqa: TRY004
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _run_summary(run):
    return {
        key: run.get(key)
        for key in (
            "id",
            "name",
            "workflow_id",
            "status",
            "conclusion",
            "head_branch",
            "head_sha",
            "run_number",
            "html_url",
            "created_at",
        )
    }


def report(facts, as_of=None):
    unavailable = list(facts.get("unavailable", []))
    candidate = facts.get("candidate")
    if not isinstance(candidate, dict) or not all(
        isinstance(candidate.get(k), str)
        and re.fullmatch(r"[0-9a-fA-F]{40}", candidate[k])
        for k in ("sha", "obi_sha")
    ):
        unavailable.append(
            "candidate Beyla/OBI source SHA (expected full 40-character SHA)"
        )
    for key in ("runs", "releases", "beyla_refs"):
        if not isinstance(facts.get(key), list):
            unavailable.append(key)
    if unavailable:
        return {
            "state": "unknown",
            "candidate": candidate,
            "unavailable": sorted(set(unavailable)),
            "next_step": "Inspect inaccessible, malformed, or incomplete GitHub facts before deciding.",
            "note": "Read-only observation; no release action was taken.",
        }

    try:
        now = _utc_datetime(as_of) if as_of else datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return {
            "state": "unknown",
            "unavailable": ["invalid as-of timestamp"],
            "next_step": "Inspect report clock input.",
        }
    week_start = (now - timedelta(days=now.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    release_dates = {"stable": [], "prerelease": []}
    for release in facts["releases"]:
        if not isinstance(release, dict) or not isinstance(
            release.get("prerelease"), bool
        ):
            return {
                "state": "unknown",
                "unavailable": ["malformed release entry"],
                "next_step": "Inspect GitHub release facts.",
            }
        stamp = release.get("published_at")
        if stamp is not None:
            try:
                published = _utc_datetime(stamp)
            except (TypeError, ValueError):
                return {
                    "state": "unknown",
                    "unavailable": ["malformed release timestamp"],
                    "next_step": "Inspect GitHub release facts.",
                }
            if published <= now:
                release_dates[
                    "prerelease" if release["prerelease"] else "stable"
                ].append(published)
    latest = {
        kind: max(items) if items else None for kind, items in release_dates.items()
    }
    stable_week = bool(latest["stable"] and latest["stable"] >= week_start)
    prerelease_week = bool(latest["prerelease"] and latest["prerelease"] >= week_start)
    observed_week = stable_week or prerelease_week
    cadence = (
        "prerelease-only-needs-policy"
        if prerelease_week and not stable_week
        else "publication-observed"
        if observed_week
        else "no-publication-observed"
    )

    runs = facts["runs"]
    if not all(isinstance(run, dict) and run.get("status") in KNOWN for run in runs):
        return {
            "state": "unknown",
            "unavailable": ["malformed or unrecognized workflow run status"],
            "next_step": "Inspect GitHub Actions facts.",
        }
    # Keep one latest attempt per workflow and branch. An old failure superseded by
    # a later successful rerun is diagnostic history, not a current blocker.
    latest_runs = {}
    for run in runs:
        key = (run.get("workflow_id", run.get("name")), run.get("head_branch"))
        order = (run.get("run_number", 0), run.get("created_at", ""))
        if key not in latest_runs or order > latest_runs[key][0]:
            latest_runs[key] = (order, run)
    active_all = [_run_summary(r) for r in runs if r["status"] in ACTIVE]
    failed_all = [
        _run_summary(r)
        for _, r in latest_runs.values()
        if r.get("conclusion") in FAILURES
    ]
    try:
        beyla_refs = set(facts["beyla_refs"])
    except TypeError:
        return {
            "state": "unknown",
            "unavailable": ["malformed release refs"],
            "next_step": "Inspect GitHub ref facts.",
        }
    if not all(isinstance(ref, str) for ref in beyla_refs):
        return {
            "state": "unknown",
            "unavailable": ["malformed release refs"],
            "next_step": "Inspect GitHub ref facts.",
        }
    state = "underway" if active_all else "needs-review" if failed_all else "candidate"
    return {
        "state": state,
        "candidate": {
            "repository": facts.get("repository"),
            "sha": candidate["sha"],
            "obi_sha": candidate["obi_sha"],
            "version": None,
        },
        "active_run_count": len(active_all),
        "active_runs": active_all[:20],
        "latest_failed_run_count": len(failed_all),
        "latest_failed_runs": failed_all[:20],
        "release_count": len(facts["releases"]),
        "latest_stable_published_at": latest["stable"].isoformat()
        if latest["stable"]
        else None,
        "latest_prerelease_published_at": latest["prerelease"].isoformat()
        if latest["prerelease"]
        else None,
        "new_publication_this_utc_week": observed_week,
        "proposed_week_start_utc": week_start.isoformat(),
        "weekly_cadence_observation": cadence,
        "release_refs": {"beyla": sorted(beyla_refs)},
        "next_step": "Wait for active preparation/tag workflow, then reconcile again."
        if active_all
        else "Review latest failed workflow attempt(s)."
        if failed_all
        else "Review the source SHA candidate and unresolved cadence/version policy; no release action was taken.",
        "note": "Read-only observation. Weekly cadence is proposed; stable/prerelease qualification and version selection require owner policy. Workflow success is not a health claim.",
    }


if __name__ == "__main__":
    print("BEGIN_RELEASE_RECONCILIATION_REPORT")
    print(json.dumps(report(json.load(sys.stdin)), indent=2, sort_keys=True))
    print("END_RELEASE_RECONCILIATION_REPORT")
