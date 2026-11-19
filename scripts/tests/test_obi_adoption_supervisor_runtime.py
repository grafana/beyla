"""Network-free API-shaped tests for the status/reconciliation runtime."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import obi_adoption_supervisor as supervisor
from obi_adoption_repair import (
    encode_state_comment,
    extract_state_comment,
    state_digest,
    validate_reservation,
)

TARGET = "a" * 40
BASE = "b" * 40
HEAD = "c" * 40
MERGE = "e" * 40
NEW_HEAD = "f" * 40
NEW_MERGE = "9" * 40
SUPERSEDED_MAIN = "8" * 40
PR = 123
DEADLINE = "2026-11-19T13:00:00Z"


class FakeGitHub:
    def __init__(self, *, head: str = HEAD, merge: str = MERGE) -> None:
        self.head = head
        self.merge = merge
        self.draft = True
        self.current_main = BASE
        self.pr_base = BASE
        self.main_pin = TARGET
        self.workflow_id_offset = 0
        self.pr_author = {
            "login": "grafana-beyla-bot[bot]",
            "id": 261436639,
            "type": "Bot",
        }
        self.comment: dict[str, object] | None = None
        self.conclusions = {
            path: "success" for path in supervisor.REQUIRED_WORKFLOW_PATHS
        }
        self.statuses = {
            path: "completed" for path in supervisor.REQUIRED_WORKFLOW_PATHS
        }
        self.last_runs: list[dict[str, object]] = []

    def request(
        self, method: str, path: str, body: dict[str, object] | None = None
    ) -> object:
        if path == f"/pulls/{PR}":
            return {
                "state": "open",
                "draft": self.draft,
                "user": self.pr_author,
                "base": {"ref": "main", "sha": self.pr_base},
                "head": {
                    "repo": {"full_name": "grafana/beyla"},
                    "ref": f"update-obi-adoption-{TARGET}",
                    "sha": self.head,
                },
                "merge_commit_sha": self.merge,
                "body": f"<!-- grafana-beyla-obi-adoption:v1 target={TARGET} base={BASE} -->",
            }
        if path == "/commits/main":
            return {"sha": self.current_main}
        if path.startswith("/contents/.obi-src?"):
            pin_sha = (
                self.main_pin if path.endswith(f"ref={self.current_main}") else TARGET
            )
            return {"type": "submodule", "sha": pin_sha}
        if path.startswith("/actions/workflows?"):
            return {
                "workflows": [
                    {
                        "path": item,
                        "id": 100 + self.workflow_id_offset + i,
                        "state": "active",
                    }
                    for i, item in enumerate(supervisor.REQUIRED_WORKFLOW_PATHS)
                ]
            }
        if path.startswith("/actions/runs?"):
            self.last_runs = [
                {
                    "workflow_id": 100 + self.workflow_id_offset + i,
                    "event": "pull_request",
                    "pull_requests": [
                        {
                            "number": PR,
                            "head": {"sha": self.head},
                            "base": {"sha": BASE},
                        }
                    ],
                    "head_sha": self.head,
                    "check_suite_id": 200 + i,
                    "id": 500 + i,
                    "run_attempt": 1,
                    "status": self.statuses[pathname],
                    "conclusion": self.conclusions[pathname],
                }
                for i, pathname in enumerate(supervisor.REQUIRED_WORKFLOW_PATHS)
            ]
            return {"workflow_runs": self.last_runs}
        if path.startswith(f"/commits/{self.head}/check-runs?"):
            return {
                "check_runs": [
                    {"check_suite": {"id": 200 + i}, "app": {"slug": "github-actions"}}
                    for i, _ in enumerate(supervisor.REQUIRED_WORKFLOW_PATHS)
                ]
            }
        if path.startswith(f"/issues/{PR}/comments?"):
            return [self.comment] if self.comment else []
        if path == "/issues/comments/999" and method == "GET":
            return self.comment or {}
        if path == f"/issues/{PR}/comments" and method == "POST":
            self.comment = {
                "id": 999,
                "body": body["body"],
                "user": {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"},
            }
            return self.comment
        if path == "/issues/comments/999" and method == "PATCH":
            assert self.comment is not None
            self.comment["body"] = body["body"]
            return self.comment
        raise AssertionError(f"unexpected fake API request {method} {path}")


def make_state(
    *, head: str = HEAD, stage: str = "waiting", used: int = 0
) -> dict[str, object]:
    state: dict[str, object] = {
        "schema_version": 1,
        "pr_number": PR,
        "target_sha": TARGET,
        "base_sha": BASE,
        "head_sha": head,
        "merge_sha": MERGE if head == HEAD else NEW_MERGE,
        "stage": stage,
        "repair_budget": {"used": used, "max": 2},
        "reservation": {"attempt": used if stage == "repairing" else 0, "digest": None},
        "deadline_utc": DEADLINE,
        "required_checks": [
            {
                "path": path,
                "workflow_id": 100 + index,
                "app_slug": "github-actions",
                "event": "pull_request",
            }
            for index, path in enumerate(supervisor.REQUIRED_WORKFLOW_PATHS)
        ],
        "evidence": [],
        "repair_failed_heads": [],
        "last_failure_run_ids": [],
    }
    if stage == "repairing":
        state["reservation"] = {"attempt": used, "digest": None}
        state["reservation"] = {"attempt": used, "digest": state_digest(state)}
    return state


def attach(fake: FakeGitHub, state: dict[str, object]) -> None:
    fake.comment = {
        "id": 999,
        "body": encode_state_comment(state, "OBI adoption status"),
        "user": {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"},
    }


def reconcile(fake: FakeGitHub, **kwargs: object) -> dict[str, object]:
    with patch.object(supervisor, "_trusted_api", return_value=fake):
        kwargs.setdefault("allow_repair", True)
        return supervisor.reconcile_status(
            pr_number=PR,
            target_sha=TARGET,
            base_sha=BASE,
            token="test-token",
            workflow_run_id=12345,
            output_path=None,
            **kwargs,
        )


def test_api_inventory_nine_success_and_one_concrete_failure() -> None:
    for failure in (False, True):
        fake = FakeGitHub()
        if failure:
            fake.conclusions[supervisor.REQUIRED_WORKFLOW_PATHS[0]] = "failure"
        attach(fake, make_state())
        result = reconcile(fake)
        assert result["stage"] == ("repairing" if failure else "ready-for-human-review")
        assert result["should_repair"] is failure
        state = extract_state_comment(fake.comment["body"])
        if failure:
            assert state["repair_budget"] == {"used": 1, "max": 2}
            assert state["reservation"]["digest"] == result["reservation_digest"]
            validate_reservation(
                state,
                pr_number=PR,
                target_sha=TARGET,
                base_sha=BASE,
                head_sha=HEAD,
                attempt=1,
                max_attempts=2,
                reservation_digest=result["reservation_digest"],
            )
        else:
            assert state["repair_budget"] == {"used": 0, "max": 2}
        assert len(state["required_checks"]) == 9
        assert all(run["app_slug"] == "github-actions" for run in state["evidence"])


def test_duplicate_event_and_no_head_worker_failure_are_terminal_without_retry() -> (
    None
):
    fake = FakeGitHub()
    fake.conclusions[supervisor.REQUIRED_WORKFLOW_PATHS[0]] = "failure"
    attach(fake, make_state(stage="repairing", used=1))
    duplicate = reconcile(fake)
    assert duplicate["reason"] == "repair-already-reserved"
    assert duplicate["should_repair"] is False
    assert extract_state_comment(fake.comment["body"])["repair_budget"]["used"] == 1

    final = reconcile(fake, worker_finished=True, no_repair=True)
    state = extract_state_comment(fake.comment["body"])
    assert final["stage"] == "blocked"
    assert state["repair_budget"] == {"used": 1, "max": 2}
    assert state["repair_failed_heads"] == [HEAD]
    repeat = reconcile(fake)
    assert repeat["stage"] == "blocked"
    assert repeat["should_repair"] is False
    assert extract_state_comment(fake.comment["body"])["repair_budget"]["used"] == 1


def test_new_head_worker_success_preserves_budget_and_waits_for_current_checks() -> (
    None
):
    fake = FakeGitHub(head=NEW_HEAD, merge=NEW_MERGE)
    fake.statuses = {path: "in_progress" for path in supervisor.REQUIRED_WORKFLOW_PATHS}
    fake.conclusions = {path: None for path in supervisor.REQUIRED_WORKFLOW_PATHS}
    attach(fake, make_state(stage="repairing", used=1))
    result = reconcile(fake, worker_finished=True, no_repair=True)
    state = extract_state_comment(fake.comment["body"])
    assert result["stage"] == "waiting"
    assert state["head_sha"] == NEW_HEAD
    assert state["repair_budget"] == {"used": 1, "max": 2}
    assert state["reservation"]["attempt"] == 0


def test_ready_for_review_pr_is_never_repaired() -> None:
    fake = FakeGitHub()
    fake.draft = False
    fake.conclusions[supervisor.REQUIRED_WORKFLOW_PATHS[0]] = "failure"
    attach(fake, make_state())
    result = reconcile(fake)
    state = extract_state_comment(fake.comment["body"])
    assert result["stage"] == "blocked"
    assert result["should_repair"] is False
    assert state["repair_budget"] == {"used": 0, "max": 2}


def test_writer_gate_off_observes_failure_without_reserving_budget() -> None:
    fake = FakeGitHub()
    fake.conclusions[supervisor.REQUIRED_WORKFLOW_PATHS[0]] = "failure"
    attach(fake, make_state())
    result = reconcile(fake, allow_repair=False)
    state = extract_state_comment(fake.comment["body"])
    assert result["stage"] == "blocked"
    assert result["reason"] == "automatic-repair-disabled-by-repository-gates"
    assert result["should_repair"] is False
    assert state["repair_budget"] == {"used": 0, "max": 2}


def test_changed_trusted_workflow_identity_fails_closed() -> None:
    fake = FakeGitHub()
    fake.workflow_id_offset = 1000
    attach(fake, make_state())
    result = reconcile(fake)
    state = extract_state_comment(fake.comment["body"])
    assert result["stage"] == "blocked"
    assert result["should_repair"] is False
    assert result["reason"] == "required-workflow-identity-changed"
    assert state["repair_budget"] == {"used": 0, "max": 2}


def test_status_and_managed_pr_require_exact_bot_identities() -> None:
    trusted_status = {
        "user": {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}
    }
    assert supervisor._author_is_trusted(trusted_status)
    assert not supervisor._author_is_trusted(
        {"user": {"login": "other[bot]", "id": 41898282, "type": "Bot"}}
    )
    assert not supervisor._author_is_trusted(
        {"user": {"login": "github-actions[bot]", "id": 1, "type": "Bot"}}
    )
    fake = FakeGitHub()
    fake.pr_author = {"login": "human", "id": 1234, "type": "User"}
    with unittest.TestCase().assertRaises(ValueError):
        supervisor._validate_live_pr(fake, PR, TARGET, BASE)


def test_new_pr_initialization_is_scoped_and_existing_budget_never_resets() -> None:
    fake = FakeGitHub()
    with patch.object(supervisor, "_trusted_api", return_value=fake):
        with unittest.TestCase().assertRaises(ValueError):
            supervisor.initialize_status(
                pr_number=PR,
                target_sha=TARGET,
                base_sha=BASE,
                head_sha=HEAD,
                token="test-token",
                new_pr=False,
            )
        with (
            patch.dict("os.environ", {supervisor.WRITER_FLAG: "false"}),
            unittest.TestCase().assertRaises(ValueError),
        ):
            supervisor.initialize_status(
                pr_number=PR,
                target_sha=TARGET,
                base_sha=BASE,
                head_sha=HEAD,
                token="test-token",
                new_pr=True,
            )
        assert fake.comment is None
        with patch.dict("os.environ", {supervisor.WRITER_FLAG: "true"}):
            created = supervisor.initialize_status(
                pr_number=PR,
                target_sha=TARGET,
                base_sha=BASE,
                head_sha=HEAD,
                token="test-token",
                new_pr=True,
            )
        assert created["initialized"] is True
        state = extract_state_comment(fake.comment["body"])
        assert state["repair_budget"] == {"used": 0, "max": 2}
        state["repair_budget"] = {"used": 1, "max": 2}
        attach(fake, state)
        existing = supervisor.initialize_status(
            pr_number=PR,
            target_sha=TARGET,
            base_sha=BASE,
            head_sha=HEAD,
            token="test-token",
            new_pr=False,
        )
        assert existing["initialized"] is False
        assert extract_state_comment(fake.comment["body"])["repair_budget"]["used"] == 1


def test_writer_and_repair_activation_flags_are_independent_and_default_off() -> None:
    assert not supervisor.repair_gate_enabled(allow_repair=True, environment={})
    assert not supervisor.repair_gate_enabled(
        allow_repair=True,
        environment={supervisor.WRITER_FLAG: "true"},
    )
    assert not supervisor.repair_gate_enabled(
        allow_repair=True,
        environment={supervisor.REPAIR_FLAG: "true"},
    )
    both = {
        supervisor.WRITER_FLAG: "true",
        supervisor.REPAIR_FLAG: "true",
    }
    assert not supervisor.repair_gate_enabled(allow_repair=False, environment=both)
    assert supervisor.repair_gate_enabled(allow_repair=True, environment=both)


def test_exact_current_main_pin_marks_superseded_without_budget_or_pr_mutation() -> (
    None
):
    fake = FakeGitHub()
    fake.current_main = SUPERSEDED_MAIN
    fake.pr_base = SUPERSEDED_MAIN
    attach(fake, make_state(used=1))
    with patch.object(supervisor, "_trusted_api", return_value=fake):
        result = supervisor.reconcile_superseded(
            pr_number=PR,
            target_sha=TARGET,
            token="test-token",
        )
    state = extract_state_comment(fake.comment["body"])
    assert result["stage"] == "superseded"
    assert state["stage"] == "superseded"
    assert state["base_sha"] == BASE
    assert state["superseded_main_sha"] == SUPERSEDED_MAIN
    assert state["repair_budget"] == {"used": 1, "max": 2}
    assert "No automatic close, retarget, draft-state change" in fake.comment["body"]


def test_superseded_observation_refuses_nonmatching_main_pin_or_untrusted_pr() -> None:
    fake = FakeGitHub()
    fake.current_main = SUPERSEDED_MAIN
    fake.pr_base = SUPERSEDED_MAIN
    fake.main_pin = "7" * 40
    attach(fake, make_state())
    with (
        patch.object(supervisor, "_trusted_api", return_value=fake),
        unittest.TestCase().assertRaises(ValueError),
    ):
        supervisor.reconcile_superseded(
            pr_number=PR,
            target_sha=TARGET,
            token="test-token",
        )
    assert extract_state_comment(fake.comment["body"])["stage"] == "waiting"

    fake.main_pin = TARGET
    fake.pr_author = {"login": "human", "id": 1234, "type": "User"}
    with (
        patch.object(supervisor, "_trusted_api", return_value=fake),
        unittest.TestCase().assertRaises(ValueError),
    ):
        supervisor.reconcile_superseded(
            pr_number=PR,
            target_sha=TARGET,
            token="test-token",
        )
    assert extract_state_comment(fake.comment["body"])["stage"] == "waiting"


def test_daily_deadline_watchdog_blocks_missing_checks_without_repair() -> None:
    fake = FakeGitHub()
    fake.statuses = {path: "in_progress" for path in supervisor.REQUIRED_WORKFLOW_PATHS}
    fake.conclusions = {path: None for path in supervisor.REQUIRED_WORKFLOW_PATHS}
    state = make_state()
    state["deadline_utc"] = "2026-11-19T11:00:00Z"
    attach(fake, state)
    result = reconcile(fake, no_repair=True)
    updated = extract_state_comment(fake.comment["body"])
    assert result["stage"] == "blocked"
    assert result["should_repair"] is False
    assert updated["repair_budget"] == {"used": 0, "max": 2}


def load_tests(
    loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str
) -> unittest.TestSuite:
    del loader, tests, pattern
    return unittest.TestSuite(
        unittest.FunctionTestCase(test)
        for name, test in sorted(globals().items())
        if name.startswith("test_") and callable(test)
    )
