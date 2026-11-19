"""Tests for the fail-closed OBI adoption supervisor policy helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import obi_adoption_supervisor as supervisor

raises = unittest.TestCase().assertRaises


def load_tests(
    loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str
) -> unittest.TestSuite:
    del loader, tests, pattern
    return unittest.TestSuite(
        unittest.FunctionTestCase(test)
        for name, test in sorted(globals().items())
        if name.startswith("test_") and callable(test)
    )


TARGET = "a" * 40
BASE = "b" * 40
HEAD = "c" * 40
NEW_HEAD = "d" * 40
PR = 123
OBSERVED = "2026-11-19T12:00:00Z"
DEADLINE = "2026-11-19T13:00:00Z"


def inventory() -> list[dict[str, object]]:
    return [
        {"path": path, "workflow_id": 100 + index}
        for index, path in enumerate(supervisor.REQUIRED_WORKFLOW_PATHS)
    ]


def runs() -> list[dict[str, object]]:
    return [
        {
            "workflow_path": path,
            "workflow_id": 100 + index,
            "app_slug": "github-actions",
            "event": "pull_request",
            "pr_number": PR,
            "target_sha": TARGET,
            "pr_head_sha": HEAD,
            "base_sha": BASE,
            "merge_sha": "e" * 40,
            "run_head_sha": HEAD,
            "expected_test_sha": "e" * 40,
            "test_sha_basis": "trusted-default-pull-request-merge-checkout",
            "run_id": 500 + index,
            "attempt": 1,
            "status": "completed",
            "conclusion": "success",
        }
        for index, path in enumerate(supervisor.REQUIRED_WORKFLOW_PATHS)
    ]


def test_managed_target_requires_exact_full_lowercase_sha() -> None:
    assert supervisor.managed_target(f"update-obi-adoption-{TARGET}") == TARGET
    assert supervisor.managed_target("update-obi-adoption-" + "A" * 40) is None
    assert supervisor.managed_target("update-obi-adoption-" + "a" * 39) is None
    assert supervisor.managed_target(f"update-obi-adoption-{TARGET}-extra") is None
    assert supervisor.managed_target("feature/unrelated") is None


def test_pr_identity_requires_exact_branch_body_and_same_repository() -> None:
    marker = f"<!-- grafana-beyla-obi-adoption:v1 target={TARGET} base={BASE} -->"
    result = supervisor.validate_pr_identity(
        branch=f"update-obi-adoption-{TARGET}",
        body=f"Adopt OBI.\n{marker}",
        pr_number=PR,
        expected_pr_number=PR,
        base_ref="main",
        head_repository="grafana/beyla",
        repository="grafana/beyla",
    )
    assert result == {"target_sha": TARGET, "base_sha": BASE, "pr_number": PR}

    bad = [
        {"body": f"{marker}\n{marker}"},
        {"body": marker.replace(TARGET, "e" * 40)},
        {"branch": "feature/ordinary"},
        {"base_ref": "release-v2.0"},
        {"head_repository": "fork/beyla"},
        {"pr_number": PR + 1},
    ]
    for change in bad:
        args = {
            "branch": f"update-obi-adoption-{TARGET}",
            "body": marker,
            "pr_number": PR,
            "expected_pr_number": PR,
            "base_ref": "main",
            "head_repository": "grafana/beyla",
            "repository": "grafana/beyla",
        }
        args.update(change)
        with raises(ValueError):
            supervisor.validate_pr_identity(**args)  # type: ignore[arg-type]


def test_inventory_is_complete_and_only_trusted_paths() -> None:
    assert len(supervisor.validate_inventory(inventory())) == len(
        supervisor.REQUIRED_WORKFLOW_PATHS
    )
    with raises(ValueError):
        supervisor.validate_inventory(inventory()[:-1])
    with raises(ValueError):
        supervisor.validate_inventory(
            inventory() + [{"path": "evil.yml", "workflow_id": 1}]
        )
    invalid_id = inventory()
    invalid_id[0]["workflow_id"] = 0
    with raises(ValueError):
        supervisor.validate_inventory(invalid_id)


def evaluate(
    check_runs: list[dict[str, object]], *, now: str = OBSERVED
) -> dict[str, object]:
    return supervisor.evaluate_required_checks(
        inventory=inventory(),
        runs=check_runs,
        pr_number=PR,
        target_sha=TARGET,
        head_sha=HEAD,
        base_sha=BASE,
        merge_sha="e" * 40,
        observed_at=now,
        deadline=DEADLINE,
    )


def test_exact_complete_required_check_set_is_human_review_ready() -> None:
    result = evaluate(runs())
    assert result["stage"] == "ready-for-human-review"
    assert result["reason"] == "all-adoption-readiness-checks-passed"


def test_missing_or_mismatched_evidence_waits_then_blocks_not_ready() -> None:
    result = evaluate(runs()[:-1])
    assert result["stage"] == "waiting"
    assert result["reason"] == "required-checks-pending"
    assert result["missing"]
    expired = evaluate(runs()[:-1], now=DEADLINE)
    assert expired["stage"] == "blocked"
    assert expired["reason"] == "required-check-evidence-unknown"

    wrong = runs()
    wrong[0]["app_slug"] = "untrusted-app"
    assert evaluate(wrong)["stage"] == "waiting"
    wrong = runs()
    wrong[0]["event"] = "push"
    assert evaluate(wrong)["stage"] == "waiting"
    wrong = runs()
    wrong[0]["pr_number"] = PR + 1
    assert evaluate(wrong)["stage"] == "waiting"
    wrong = runs()
    wrong[0]["pr_head_sha"] = NEW_HEAD
    assert evaluate(wrong)["stage"] == "waiting"
    wrong = runs()
    wrong[0]["base_sha"] = NEW_HEAD
    assert evaluate(wrong)["stage"] == "waiting"
    wrong = runs()
    wrong[0]["run_head_sha"] = NEW_HEAD
    assert evaluate(wrong)["stage"] == "waiting"
    wrong = runs()
    wrong[0]["merge_sha"] = NEW_HEAD
    assert evaluate(wrong)["stage"] == "waiting"


def test_nonterminal_required_check_waits_until_deadline() -> None:
    pending = runs()
    pending[0]["status"] = "in_progress"
    pending[0]["conclusion"] = None
    assert evaluate(pending)["stage"] == "waiting"
    assert evaluate(pending, now=DEADLINE)["stage"] == "blocked"


def test_skipped_or_cancelled_is_not_ready_or_repairable() -> None:
    for conclusion in ("skipped", "cancelled", "neutral", "action_required"):
        evidence = runs()
        evidence[0]["conclusion"] = conclusion
        result = evaluate(evidence)
        assert result["stage"] == "waiting"
        assert result["repairable_run_ids"] == []
        assert evaluate(evidence, now=DEADLINE)["stage"] == "blocked"


def test_concrete_failure_is_repairable_only_when_entire_set_is_terminal() -> None:
    failed = runs()
    failed[0]["conclusion"] = "failure"
    assert evaluate(failed)["stage"] == "repairable"
    assert evaluate(failed)["repairable_run_ids"] == [500]
    incomplete = failed[:-1]
    assert evaluate(incomplete)["stage"] == "waiting"


def test_latest_workflow_attempt_is_evaluated() -> None:
    evidence = runs()
    latest = dict(evidence[0])
    latest.update(run_id=900, attempt=2, conclusion="failure")
    assert evaluate(evidence + [latest])["stage"] == "repairable"


def test_api_shaped_current_nine_run_inventory_passes_and_concrete_failure_repairs() -> (
    None
):
    class FakeGitHub:
        def __init__(self, failure: bool = False) -> None:
            self.failure = failure
            self.paths = list(supervisor.REQUIRED_WORKFLOW_PATHS)

        def request(self, method: str, path: str) -> dict[str, object]:
            del method
            if path.startswith("/actions/workflows?"):
                return {
                    "workflows": [
                        {"path": item, "id": 100 + index, "state": "active"}
                        for index, item in enumerate(self.paths)
                    ]
                }
            if path.startswith("/actions/runs?"):
                return {
                    "workflow_runs": [
                        {
                            "workflow_id": 100 + index,
                            "event": "pull_request",
                            "pull_requests": [
                                {
                                    "number": PR,
                                    "head": {"sha": HEAD},
                                    "base": {"sha": BASE},
                                }
                            ],
                            "head_sha": HEAD,
                            "check_suite_id": 200 + index,
                            "id": 500 + index,
                            "run_attempt": 1,
                            "status": "completed",
                            "conclusion": "failure"
                            if self.failure and index == 0
                            else "success",
                        }
                        for index, _ in enumerate(self.paths)
                    ]
                }
            if path.startswith(f"/commits/{HEAD}/check-runs?"):
                return {
                    "check_runs": [
                        {
                            "check_suite": {"id": 200 + index},
                            "app": {"slug": "github-actions"},
                        }
                        for index, _ in enumerate(self.paths)
                    ]
                }
            raise AssertionError(f"unexpected fake API path {path}")

    for failed in (False, True):
        trusted_inventory, evidence = supervisor._read_required_runs(
            FakeGitHub(failure=failed),
            pr_number=PR,
            head_sha=HEAD,
            base_sha=BASE,
            merge_sha="e" * 40,
        )
        result = supervisor.evaluate_required_checks(
            inventory=trusted_inventory,
            runs=evidence,
            pr_number=PR,
            target_sha=TARGET,
            head_sha=HEAD,
            base_sha=BASE,
            merge_sha="e" * 40,
            observed_at=OBSERVED,
            deadline=DEADLINE,
        )
        assert result["stage"] == ("repairable" if failed else "ready-for-human-review")


def test_stale_or_push_run_does_not_poison_or_satisfy_current_pr_evidence() -> None:
    evidence = runs()
    stale = dict(evidence[0], run_id=800, attempt=1, pr_head_sha=NEW_HEAD)
    push = dict(evidence[1], run_id=801, event="push")
    assert evaluate(evidence + [stale, push])["stage"] == "ready-for-human-review"

    # A push run alone must never qualify as the expected PR workflow.
    only_push = [
        run for run in evidence if run["workflow_path"] != evidence[1]["workflow_path"]
    ]
    only_push.append(push)
    assert evaluate(only_push)["stage"] == "waiting"


def test_budget_is_per_pr_and_target_and_survives_head_changes() -> None:
    first = supervisor.next_repair_budget(
        prior_state=None,
        pr_number=PR,
        target_sha=TARGET,
        base_sha=BASE,
        head_sha=HEAD,
    )
    assert first["allowed"] is True
    assert first["attempt"] == first["used"] == 1

    # Even though the bot-created head changed, the PR+target budget advances.
    next_state = {
        "schema_version": 1,
        "pr_number": PR,
        "target_sha": TARGET,
        "base_sha": BASE,
        "head_sha": NEW_HEAD,
        "stage": "blocked",
        "repair_budget": {"used": 1, "max": 2},
    }
    second = supervisor.next_repair_budget(
        prior_state=next_state,
        pr_number=PR,
        target_sha=TARGET,
        base_sha=BASE,
        head_sha=NEW_HEAD,
    )
    assert second["attempt"] == second["used"] == 2
    exhausted = {**next_state, "repair_budget": {"used": 2, "max": 2}}
    assert (
        supervisor.next_repair_budget(
            prior_state=exhausted,
            pr_number=PR,
            target_sha=TARGET,
            base_sha=BASE,
            head_sha=NEW_HEAD,
        )["allowed"]
        is False
    )


def test_budget_corruption_or_mismatched_identity_fails_closed() -> None:
    state = {
        "schema_version": 1,
        "pr_number": PR,
        "target_sha": TARGET,
        "base_sha": BASE,
        "head_sha": HEAD,
        "stage": "blocked",
        "repair_budget": {"used": 1, "max": 2},
    }
    with raises(ValueError):
        supervisor.next_repair_budget(
            prior_state=state,
            pr_number=PR,
            target_sha="e" * 40,
            base_sha=BASE,
            head_sha=HEAD,
        )
    with raises(ValueError):
        supervisor.next_repair_budget(
            prior_state={**state, "repair_budget": {"used": "1", "max": 2}},
            pr_number=PR,
            target_sha=TARGET,
            base_sha=BASE,
            head_sha=HEAD,
        )


def test_repeated_reserved_event_does_not_consume_or_launch_again() -> None:
    state = {
        "schema_version": 1,
        "pr_number": PR,
        "target_sha": TARGET,
        "base_sha": BASE,
        "head_sha": HEAD,
        "stage": "repairing",
        "repair_budget": {"used": 1, "max": 2},
        "reservation": {"attempt": 1, "digest": "a" * 64},
    }
    result = supervisor.next_repair_budget(
        prior_state=state,
        pr_number=PR,
        target_sha=TARGET,
        base_sha=BASE,
        head_sha=HEAD,
    )
    assert result["allowed"] is False
    assert result["reason"] == "repair-already-reserved"
