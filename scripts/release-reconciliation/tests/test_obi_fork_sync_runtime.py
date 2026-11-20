"""Hermetic API-contract and recurring-sync regression tests."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "adoption"))
import obi_fork_sync as sync


U = "a" * 40
V = "b" * 40
F = "c" * 40
S = "d" * 40
RUN_ID = "1234567"


def managed_pr(number: int, target: str, merge_sha: str) -> dict:
    branch = f"sync-obi-upstream-{target}"
    return {
        "number": number,
        "state": "closed",
        "merged_at": "2026-11-20T10:00:00Z",
        "merge_commit_sha": merge_sha,
        "body": f"<!-- grafana-obi-fork-sync:v1 target={target} base={F} -->",
        "head": {
            "ref": branch,
            "sha": target,
            "repo": {"full_name": sync.FORK_REPO},
        },
        "base": {"ref": "main", "repo": {"full_name": sync.FORK_REPO}},
    }


class DispatchContractTests(unittest.TestCase):
    def test_request_inventory_requires_official_workflow_bot_event_identity(self):
        valid = {
            "workflow_id": 20,
            "actor": {"login": "github-actions[bot]"},
            "display_title": sync.request_title(U, RUN_ID),
            "event": "workflow_dispatch",
            "head_branch": "main",
            "id": 801,
            "created_at": "2026-11-20T09:00:00Z",
            "status": "completed",
            "conclusion": "success",
        }
        rows = [
            valid,
            {**valid, "id": 802, "actor": {"login": "human"}},
            {**valid, "id": 803, "workflow_id": 999},
            {**valid, "id": 804, "event": "schedule"},
            {**valid, "id": 805, "head_branch": "feature"},
        ]

        class FakeAPI:
            def get(self, path):
                if path == f"/actions/workflows/{sync.FORK_WORKFLOW}":
                    return {"id": 20}
                if path.startswith("/actions/workflows/20/runs?"):
                    return {"workflow_runs": rows}
                raise AssertionError(f"Unexpected API GET: {path}")

        self.assertEqual(
            sync.request_runs(FakeAPI()),
            [
                {
                    "target_sha": U,
                    "origin_run_id": RUN_ID,
                    "run_id": "801",
                    "created_at": "2026-11-20T09:00:00Z",
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        )

    def test_request_dispatch_asks_for_run_details_and_verifies_run_identity(self):
        calls = []

        class FakeAPI:
            def __init__(self, token, repository):
                self.repository = repository

            def get(self, path):
                if path == f"/actions/runs/{RUN_ID}":
                    return {
                        "head_branch": "main",
                        "workflow_id": 10,
                        "event": "schedule",
                    }
                if path == f"/actions/workflows/{sync.ADOPTION_WORKFLOW}":
                    return {"id": 10}
                if path == f"/actions/workflows/{sync.FORK_WORKFLOW}":
                    return {"id": 20}
                if path.startswith("/actions/workflows/20/runs?"):
                    return {"workflow_runs": []}
                if path == "/actions/runs/987654321":
                    return {
                        "workflow_id": 20,
                        "event": "workflow_dispatch",
                        "head_branch": "main",
                        "display_title": sync.request_title(U, RUN_ID),
                    }
                raise AssertionError(f"Unexpected API GET: {path}")

            def request(self, method, path, body=None):
                calls.append((method, path, body))
                return {"workflow_run_id": 987654321}, 200

        env = {
            "GH_TOKEN": "fake-token",
            "OBI_SHA": U,
            "REQUEST_RUN_ID": RUN_ID,
            "GITHUB_REF": "refs/heads/main",
        }
        with (
            patch.dict(os.environ, env, clear=False),
            patch.object(sync, "GitHubAPI", FakeAPI),
        ):
            sync.create_request()

        self.assertEqual(len(calls), 1)
        method, path, body = calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(path, f"/actions/workflows/{sync.FORK_WORKFLOW}/dispatches")
        self.assertEqual(
            body,
            {
                "ref": "main",
                "return_run_details": True,
                "inputs": {"obi_sha": U, "request_run_id": RUN_ID},
            },
        )


class RecurringHistoryTests(unittest.TestCase):
    def test_second_sync_can_follow_a_verified_prior_merge_parent(self):
        plan = sync.choose_sync_action(
            target_sha=V,
            fork_main_sha=S,
            object_visible=True,
            target_is_ancestor=False,
            compare_status="diverged",
            merge_base_sha=U,
            managed_merge_base=True,
            managed_open=[],
            exact_closed=[],
            branch_exists=False,
        )
        self.assertEqual(plan["action"], "create")

    def test_divergence_without_the_exact_managed_merge_parent_is_held(self):
        plan = sync.choose_sync_action(
            target_sha=V,
            fork_main_sha=S,
            object_visible=True,
            target_is_ancestor=False,
            compare_status="diverged",
            merge_base_sha=U,
            managed_merge_base=False,
            managed_open=[],
            exact_closed=[],
            branch_exists=False,
        )
        self.assertEqual(plan["action"], "hold")


class GlobalReservationTests(unittest.TestCase):
    def test_reserved_target_on_one_managed_pr_is_not_dispatched_from_another(self):
        """A later containing PR must not bypass an existing per-target reservation."""
        first = managed_pr(41, U, S)
        second = managed_pr(42, U, "e" * 40)
        first_comment = {
            "id": 501,
            "user": {"id": sync.BOT_ID, "login": sync.BOT_LOGIN},
            "body": sync.render_status_comment(
                {
                    "schema_version": 1,
                    "pr_number": 41,
                    "target_sha": U,
                    "base_sha": F,
                    "continuations": [
                        {
                            "target_sha": U,
                            "origin_run_ids": [RUN_ID],
                            "stage": "dispatched",
                            "dispatch_run_id": 777,
                        }
                    ],
                }
            ),
        }
        second_comment = {
            "id": 502,
            "user": {"id": sync.BOT_ID, "login": sync.BOT_LOGIN},
            "body": sync.render_status_comment(
                {
                    "schema_version": 1,
                    "pr_number": 42,
                    "target_sha": U,
                    "base_sha": F,
                    "continuations": [],
                }
            ),
        }
        dispatches = []

        class FakeAPI:
            def __init__(self, token, repository):
                self.repository = repository

            def get(self, path):
                if path == f"/actions/workflows/{sync.FORK_WORKFLOW}":
                    return {"id": 20}
                if path == f"/actions/workflows/{sync.ADOPTION_WORKFLOW}":
                    return {"id": 10}
                if path == f"/actions/runs/{RUN_ID}":
                    return {
                        "id": int(RUN_ID),
                        "workflow_id": 10,
                        "head_branch": "main",
                        "event": "schedule",
                    }
                if path == "/actions/runs/777":
                    return {"workflow_id": 10, "status": "completed"}
                if path == "/contents/.obi-src?ref=main":
                    return {"sha": V}
                if path == "/commits/main":
                    return {"sha": V}
                if path.startswith("/compare/"):
                    old = path.split("/compare/", 1)[1].split("...", 1)[0]
                    return {"status": "ahead", "merge_base_commit": {"sha": old}}
                if path.startswith("https://api.github.com/search/issues?"):
                    return {
                        "total_count": 2,
                        "incomplete_results": False,
                        "items": [{"number": 41}, {"number": 42}],
                    }
                if path == "/pulls/41":
                    return first
                if path == "/pulls/42":
                    return second
                if path.startswith("/issues/") and path.endswith("/comments"):
                    number = int(path.split("/")[2])
                    return [first_comment if number == 41 else second_comment]
                raise AssertionError(f"Unexpected API GET: {path}")

            def paginate(self, path, max_pages=sync.MAX_PAGES):
                if path == "/pulls?state=closed&base=main":
                    return [first, second], True
                if path == "/pulls?state=open&base=main":
                    return [], True
                if (
                    path
                    == f"/pulls?state=closed&base=main&head=grafana:sync-obi-upstream-{U}"
                ):
                    return [], True
                if (
                    path
                    == f"/pulls?state=closed&base=main&head=grafana:update-obi-adoption-{U}"
                ):
                    return [], True
                if path == "/issues/41/comments":
                    return [first_comment], True
                if path == "/issues/42/comments":
                    return [second_comment], True
                raise AssertionError(f"Unexpected API pagination: {path}")

            def request(self, method, path, body=None):
                if method == "GET" and path.startswith("/actions/workflows/"):
                    return self.get(path), 200
                if method == "PATCH":
                    return {"body": body["body"]}, 200
                if method == "POST" and path.endswith("/dispatches"):
                    dispatches.append((self.repository, body))
                    return {"workflow_run_id": 888}, 200
                raise AssertionError(f"Unexpected API request: {method} {path}")

        class FakeReadAPI(FakeAPI):
            def get(self, path):
                if path.startswith("/actions/workflows/") and path.endswith(
                    "/runs?event=workflow_dispatch&branch=main&per_page=100&page=1"
                ):
                    return {
                        "workflow_runs": [
                            {
                                "workflow_id": 20,
                                "actor": {"login": "github-actions[bot]"},
                                "display_title": sync.request_title(U, RUN_ID),
                                "event": "workflow_dispatch",
                                "head_branch": "main",
                                "id": 700,
                                "created_at": "2026-11-20T09:00:00Z",
                                "status": "completed",
                                "conclusion": "success",
                            }
                        ]
                    }
                if path == "/actions/workflows/10/runs?branch=main&per_page=100&page=1":
                    return {"workflow_runs": []}
                if (
                    path
                    == "/actions/workflows/10/runs?event=workflow_dispatch&branch=main&per_page=100&page=1"
                ):
                    return {"workflow_runs": []}
                return super().get(path)

        def api_factory(token, repository):
            if token == "read-token":
                return FakeReadAPI(token, repository)
            return FakeAPI(token, repository)

        env = {"APP_TOKEN": "app-token", "GITHUB_TOKEN": "read-token"}
        with (
            patch.dict(os.environ, env, clear=False),
            patch.object(sync, "GitHubAPI", side_effect=api_factory),
        ):
            sync.poll_continuations()

        self.assertEqual(dispatches, [])


class ContinuationHappyPathTests(unittest.TestCase):
    def test_reserve_dispatch_verify_and_reconcile_never_dispatches_twice(self):
        pr = managed_pr(51, U, S)
        comment = {
            "id": 601,
            "user": {"id": sync.BOT_ID, "login": sync.BOT_LOGIN},
            "body": sync.render_status_comment(
                {
                    "schema_version": 1,
                    "pr_number": 51,
                    "target_sha": U,
                    "base_sha": F,
                    "continuations": [],
                }
            ),
        }
        post_calls = []
        comment_patches = []
        child_run_gets = []

        class FakeAPI:
            def __init__(self, token, repository):
                self.token = token
                self.repository = repository

            def get(self, path):
                if path == f"/actions/workflows/{sync.FORK_WORKFLOW}":
                    return {"id": 20}
                if path == f"/actions/workflows/{sync.ADOPTION_WORKFLOW}":
                    return {"id": 10}
                if path.startswith("/actions/workflows/20/runs?event="):
                    return {
                        "workflow_runs": [
                            {
                                "workflow_id": 20,
                                "actor": {"login": "github-actions[bot]"},
                                "display_title": sync.request_title(U, RUN_ID),
                                "event": "workflow_dispatch",
                                "head_branch": "main",
                                "id": 701,
                                "created_at": "2026-11-20T09:00:00Z",
                                "status": "completed",
                                "conclusion": "success",
                            }
                        ]
                    }
                if path == "/actions/workflows/10/runs?branch=main&per_page=100&page=1":
                    return {"workflow_runs": []}
                if (
                    path
                    == "/actions/workflows/10/runs?event=workflow_dispatch&branch=main&per_page=100&page=1"
                ):
                    return {"workflow_runs": []}
                if path == f"/actions/runs/{RUN_ID}":
                    return {
                        "id": int(RUN_ID),
                        "workflow_id": 10,
                        "head_branch": "main",
                        "event": "schedule",
                    }
                if path == "/actions/runs/888":
                    child_run_gets.append(path)
                    return {
                        "id": 888,
                        "workflow_id": 10,
                        "head_branch": "main",
                        "event": "workflow_dispatch",
                        "display_title": sync.adoption_title(U, RUN_ID),
                        "status": "completed",
                    }
                if path == "/commits/main":
                    if self.repository == sync.FORK_REPO:
                        return {"sha": V}
                    if (
                        self.repository
                        == "open-telemetry/opentelemetry-ebpf-instrumentation"
                    ):
                        return {"sha": V}
                if path == "/contents/.obi-src?ref=main":
                    return {"sha": F}
                if path.startswith("/compare/"):
                    older, newer = path.split("/compare/", 1)[1].split("...", 1)
                    if (older, newer) == (U, F):
                        status, merge_base = "behind", F
                    elif older == newer:
                        status, merge_base = "identical", older
                    else:
                        status, merge_base = "ahead", older
                    return {"status": status, "merge_base_commit": {"sha": merge_base}}
                if path.startswith("https://api.github.com/search/issues?"):
                    return {
                        "total_count": 1,
                        "incomplete_results": False,
                        "items": [{"number": 51}],
                    }
                if path == "/pulls/51":
                    return pr
                raise AssertionError(f"Unexpected API GET ({self.repository}): {path}")

            def paginate(self, path, max_pages=sync.MAX_PAGES):
                if path == "/pulls?state=open&base=main":
                    return [], True
                if (
                    path
                    == "/pulls?state=closed&base=main&head=grafana:sync-obi-upstream-"
                    + U
                ):
                    return [pr], True
                if (
                    path
                    == "/pulls?state=closed&base=main&head=grafana:update-obi-adoption-"
                    + U
                ):
                    return [], True
                if path == "/issues/51/comments":
                    return [comment], True
                raise AssertionError(
                    f"Unexpected API pagination ({self.repository}): {path}"
                )

            def request(self, method, path, body=None):
                if method == "GET":
                    return self.get(path), 200
                if method == "PATCH" and path == "/issues/comments/601":
                    comment["body"] = body["body"]
                    comment_patches.append(body["body"])
                    return {"body": body["body"]}, 200
                if method == "POST" and path.endswith("/dispatches"):
                    post_calls.append((self.repository, path, body))
                    return {"workflow_run_id": 888}, 200
                raise AssertionError(f"Unexpected API request: {method} {path}")

        env = {"APP_TOKEN": "app-token", "GITHUB_TOKEN": "dispatch-token"}
        with (
            patch.dict(os.environ, env, clear=False),
            patch.object(sync, "GitHubAPI", FakeAPI),
        ):
            sync.poll_continuations()
            reserved_and_dispatched = sync.parse_status_comment(comment["body"])
            self.assertEqual(
                reserved_and_dispatched["continuations"][0]["stage"], "dispatched"
            )
            self.assertEqual(
                reserved_and_dispatched["continuations"][0]["dispatch_run_id"], 888
            )
            sync.poll_continuations()

        self.assertEqual(len(post_calls), 1)
        self.assertEqual(child_run_gets, ["/actions/runs/888", "/actions/runs/888"])
        self.assertEqual(post_calls[0][0], sync.BEYLA_REPO)
        self.assertEqual(
            post_calls[0][1], f"/actions/workflows/{sync.ADOPTION_WORKFLOW}/dispatches"
        )
        self.assertEqual(
            post_calls[0][2],
            {
                "ref": "main",
                "return_run_details": True,
                "inputs": {"obi_sha": U, "request_run_id": RUN_ID},
            },
        )
        final_state = sync.parse_status_comment(comment["body"])
        self.assertEqual(final_state["continuations"][0]["stage"], "blocked")
        self.assertEqual(final_state["continuations"][0]["dispatch_run_id"], 888)


if __name__ == "__main__":
    unittest.main()
