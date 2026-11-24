"""Pure decision logic for the read-only exact-SHA OBI adoption preflight."""

import re
from datetime import datetime, timezone

SHA = re.compile(r"^[0-9a-f]{40}$")


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except ValueError:
        return None


def reconcile(facts, now):
    run, source = facts.get("run", {}), facts.get("source", {})
    upstream, pin = (source.get(key) for key in ("upstream_sha", "pin_sha"))
    result = {
        "schema_version": 1,
        "observed_at": now,
        "run": {key: run.get(key) for key in ("run_id", "attempt", "ref", "head_sha")},
        "source": {
            "upstream_sha": upstream,
            "pin_sha": pin,
            "graph_complete": source.get("graph_complete") is True,
            "timestamps_valid": source.get("timestamps_valid"),
            "pin_is_ancestor": source.get("pin_is_ancestor"),
            "upstream_is_ancestor_of_pin": source.get("upstream_is_ancestor_of_pin"),
            "snapshot_current_main": source.get("snapshot_current_main"),
            "main_head_sha": source.get("main_head_sha"),
        },
        "pending": {
            "count": source.get("pending_count"),
            "oldest_sha": source.get("oldest_sha"),
            "oldest_committer_at": source.get("oldest_committer_at"),
            "age_hours": None,
            "freshness": "unknown",
        },
        "inventory": {
            "open_pr_complete": facts.get("open_pr_inventory_complete") is True,
            "closed_target_history_complete": facts.get(
                "closed_target_history_complete"
            )
            is True,
        },
        "collection_error": facts.get("collection_error"),
        "adoption": {
            "outcome": "unknown",
            "active_prs": facts.get("active_prs", []),
            "blocker": None,
            "next_action": "Inspect missing or inconsistent source facts.",
        },
    }
    adoption, pending = result["adoption"], result["pending"]
    if facts.get("collection_error"):
        adoption["blocker"] = (
            "Source or PR collection failed; partial facts are not actionable."
        )
        return result
    if not all(
        isinstance(value, str) and SHA.fullmatch(value) for value in (upstream, pin)
    ):
        adoption["blocker"] = "Missing or non-full upstream or current-pin SHA."
        return result
    if source.get("snapshot_current_main") is not True:
        adoption["blocker"] = "Workflow snapshot is no longer the current main head."
        return result
    if upstream == pin:
        pending.update(count=0, age_hours=0, freshness="fresh")
        if facts.get("active_prs"):
            adoption.update(
                outcome="active",
                blocker="Main already has the sampled pin while an adoption PR remains open.",
                next_action="Preserve the managed PR and reconcile its current state for human disposition; do not repair or close it.",
            )
            return result
        adoption.update(
            outcome="no-op",
            blocker=None,
            next_action="Sampled upstream equals the current pin; no adoption change is needed.",
        )
        return result
    if (
        source.get("graph_complete") is True
        and source.get("upstream_is_ancestor_of_pin") is True
    ):
        adoption.update(
            outcome="superseded",
            blocker="Current pin is already newer than sampled upstream.",
            next_action="Do not roll back; report that this sampled target is superseded.",
        )
        return result
    if (
        source.get("graph_complete") is not True
        or source.get("pin_is_ancestor") is not True
    ):
        adoption["blocker"] = (
            "Complete ancestry could not prove current pin is an ancestor of sampled upstream."
        )
        return result
    count = source.get("pending_count")
    if not isinstance(count, int) or count < 0:
        adoption["blocker"] = "Pending commit set is incomplete."
        return result
    if count:
        stamp, now_dt = parse_time(source.get("oldest_committer_at")), parse_time(now)
        if (
            source.get("timestamps_valid") is True
            and stamp is not None
            and now_dt is not None
            and stamp <= now_dt
        ):
            age = (now_dt - stamp).total_seconds() / 3600
            pending.update(
                age_hours=round(age, 3), freshness="stale" if age >= 24 else "fresh"
            )
    else:
        pending.update(age_hours=0, freshness="fresh")
    if facts.get("active_prs"):
        adoption.update(
            outcome="active",
            blocker="An adoption PR is already open; do not retarget it.",
            next_action="Preserve the active PR; report the sampled target and defer a second PR.",
        )
        return result
    if facts.get("rejected_exact_target"):
        adoption.update(
            outcome="rejected",
            blocker="Exact target has a closed, unmerged adoption PR.",
            next_action="Request explicit human retry authorization; do not respawn automatically.",
        )
        return result
    if facts.get("closed_exact_target"):
        adoption.update(
            outcome="superseded",
            blocker="Exact target already has a closed adoption PR.",
            next_action="Do not create a duplicate target PR; inspect its existing disposition.",
        )
        return result
    if facts.get("open_pr_inventory_complete") is not True:
        adoption["blocker"] = "Open adoption PR inventory is incomplete."
        return result
    closed_complete = facts.get("closed_target_history_complete") is True
    adoption.update(
        outcome="source-candidate",
        blocker=None
        if closed_complete
        else "Closed-PR history scan was bounded; retry/supersession eligibility remains unknown.",
        next_action="Source facts are consistent; confirm historical rejection and all publication rules before human review.",
    )
    return result
