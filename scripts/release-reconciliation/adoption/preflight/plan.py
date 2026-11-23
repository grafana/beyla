"""Choose whether a trusted publisher may prepare a candidate from a read-only report."""


def publish_plan(report, repository="grafana/beyla"):
    """Return a deterministic action; this is eligibility, never merge/release permission."""
    source = report.get("source", {})
    adoption = report.get("adoption", {})
    outcome = adoption.get("outcome")
    target = source.get("upstream_sha")
    base = source.get("main_head_sha")
    branch = f"update-obi-adoption-{target}" if target else None
    result = {
        "action": "blocked",
        "reason": adoption.get("blocker") or "Incomplete preflight facts.",
        "target_sha": target,
        "base_sha": base,
        "branch": branch,
        "pr_number": None,
        "expected_pr_head": None,
    }
    if report.get("collection_error") or not source.get("snapshot_current_main"):
        return result
    active = adoption.get("active_prs", [])
    if active:
        if source.get("upstream_sha") == source.get("pin_sha") and len(active) == 1:
            pr = active[0]
            if (
                pr.get("target_sha") == target
                and pr.get("head_branch") == branch
                and pr.get("head_repo") == repository
                and pr.get("managed_marker")
            ):
                return {
                    **result,
                    "action": "superseded",
                    "reason": "Main already has this exact target while its managed PR remains open; preserve it for human disposition.",
                    "pr_number": pr.get("number"),
                    "expected_pr_head": pr.get("head_sha"),
                }
        if len(active) != 1:
            return {
                **result,
                "action": "defer",
                "reason": "Multiple active OBI pin PRs; preserve and reconcile manually.",
            }
        pr = active[0]
        if pr.get("target_sha") != target:
            return {
                **result,
                "action": "defer",
                "reason": "An active PR targets a different OBI SHA; preserve it and do not retarget.",
            }
        if (
            pr.get("head_branch") != branch
            or pr.get("head_repo") != repository
            or not pr.get("managed_marker")
        ):
            return {
                **result,
                "action": "defer",
                "reason": "The active target PR is not this writer's managed branch/marker.",
            }
        if pr.get("managed_base_sha") != base:
            return {
                **result,
                "action": "defer",
                "reason": "The managed PR was prepared against another main base; do not silently rebase.",
            }
        return {
            **result,
            "action": "observe",
            "reason": "Preserve the active managed PR; do not overwrite its head.",
            "pr_number": pr.get("number"),
            "expected_pr_head": pr.get("head_sha"),
        }
    if outcome == "no-op":
        return {
            **result,
            "action": "no-op",
            "reason": "Current Beyla pin equals sampled upstream.",
        }
    if outcome != "source-candidate":
        return result
    if report.get("inventory", {}).get("open_pr_complete") is not True:
        return {**result, "reason": "Open adoption PR inventory is incomplete."}
    if report.get("inventory", {}).get("closed_target_history_complete") is not True:
        return {
            **result,
            "reason": "Exact-target closed-PR history is incomplete; do not respawn a possibly rejected SHA.",
        }
    return {
        **result,
        "action": "create",
        "reason": "Exact source is consistent and no active or rejected target PR was found.",
    }
