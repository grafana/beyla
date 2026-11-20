import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "adoption"))
import obi_fork_sync as fork_sync


SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def pr(target=SHA_A, base=SHA_B, number=1, state="open", merged_at=None, head_sha=None):
    branch = f"sync-obi-upstream-{target}"
    return {
        "number": number,
        "state": state,
        "merged_at": merged_at,
        "merge_commit_sha": head_sha or SHA_C,
        "body": f"<!-- grafana-obi-fork-sync:v1 target={target} base={base} -->\nMerge using a merge commit.",
        "head": {
            "ref": branch,
            "sha": head_sha or target,
            "repo": {"full_name": fork_sync.FORK_REPO},
        },
        "base": {"ref": "main", "repo": {"full_name": fork_sync.FORK_REPO}},
    }


def run(
    target=SHA_A, origin="123", run_id=10, status="completed", conclusion="success"
):
    return {
        "display_title": fork_sync.request_title(target, origin),
        "event": "workflow_dispatch",
        "head_branch": "main",
        "status": status,
        "conclusion": conclusion,
        "id": run_id,
        "created_at": "2026-11-20T10:00:00Z",
    }


class ForkSyncPureTests(unittest.TestCase):
    def test_request_title_is_exact_and_parseable(self):
        self.assertEqual(
            fork_sync.request_title(SHA_A, "123"),
            f"OBI fork sync target {SHA_A} request 123",
        )
        self.assertEqual(fork_sync.parse_request_run(run())["target_sha"], SHA_A)
        self.assertIsNone(
            fork_sync.parse_request_run({**run(), "head_branch": "feature"})
        )
        self.assertIsNone(fork_sync.parse_request_run({**run(), "event": "schedule"}))

    def test_create_requires_exact_object_and_fast_forward_candidate(self):
        common = dict(
            target_sha=SHA_A,
            fork_main_sha=SHA_B,
            target_is_ancestor=False,
            managed_open=[],
            exact_closed=[],
            branch_exists=False,
        )
        self.assertEqual(
            fork_sync.choose_sync_action(
                **common, object_visible=False, compare_status="ahead"
            )["action"],
            "hold",
        )
        self.assertEqual(
            fork_sync.choose_sync_action(
                **common,
                object_visible=True,
                compare_status="ahead",
                merge_base_sha=SHA_B,
            )["action"],
            "create",
        )
        self.assertEqual(
            fork_sync.choose_sync_action(
                **common,
                object_visible=True,
                compare_status="diverged",
                merge_base_sha=SHA_B,
            )["action"],
            "hold",
        )

    def test_second_sync_cycle_accepts_verified_prior_managed_merge_base(self):
        # F0 -> PR(U) -> human merge S, then upstream advances to V. S and V
        # diverge, but U is the verified common base and the new PR preserves S.
        result = fork_sync.choose_sync_action(
            target_sha=SHA_C,
            fork_main_sha=SHA_B,
            object_visible=True,
            target_is_ancestor=False,
            compare_status="diverged",
            merge_base_sha=SHA_A,
            managed_merge_base=True,
            managed_open=[],
            exact_closed=[],
            branch_exists=False,
        )
        self.assertEqual(result["action"], "create")

    def test_active_pr_is_observed_or_deferred_never_retargeted(self):
        common = dict(
            target_sha=SHA_A,
            fork_main_sha=SHA_B,
            object_visible=True,
            target_is_ancestor=False,
            compare_status="ahead",
            exact_closed=[],
            branch_exists=False,
        )
        self.assertEqual(
            fork_sync.choose_sync_action(**common, managed_open=[pr()])["action"],
            "observe",
        )
        self.assertEqual(
            fork_sync.choose_sync_action(**common, managed_open=[pr(SHA_C)])["action"],
            "defer",
        )
        self.assertEqual(
            fork_sync.choose_sync_action(**common, managed_open=[pr(), pr(SHA_C)])[
                "action"
            ],
            "hold",
        )

    def test_malformed_managed_pr_identity_still_blocks_new_writer(self):
        malformed = pr()
        malformed["head"]["sha"] = SHA_C
        result = fork_sync.choose_sync_action(
            target_sha=SHA_A,
            fork_main_sha=SHA_B,
            object_visible=True,
            target_is_ancestor=False,
            compare_status="ahead",
            managed_open=[malformed],
            exact_closed=[],
            branch_exists=False,
        )
        self.assertEqual(result["action"], "hold")

    def test_rejected_target_and_unowned_branch_block_creation(self):
        common = dict(
            target_sha=SHA_A,
            fork_main_sha=SHA_B,
            object_visible=True,
            target_is_ancestor=False,
            compare_status="ahead",
            managed_open=[],
        )
        rejected = pr(state="closed")
        self.assertEqual(
            fork_sync.choose_sync_action(
                **common, exact_closed=[rejected], branch_exists=False
            )["action"],
            "hold",
        )
        self.assertEqual(
            fork_sync.choose_sync_action(**common, exact_closed=[], branch_exists=True)[
                "action"
            ],
            "hold",
        )

    def test_reachable_target_is_noop_without_needing_equal_branch_tip(self):
        result = fork_sync.choose_sync_action(
            target_sha=SHA_A,
            fork_main_sha=SHA_B,
            object_visible=True,
            target_is_ancestor=True,
            compare_status="behind",
            managed_open=[],
            exact_closed=[],
            branch_exists=False,
        )
        self.assertEqual(result["action"], "synced")

    def test_request_runs_collapse_duplicate_targets_and_reject_conflict(self):
        selected = fork_sync.select_requests([run(run_id=10), run(run_id=11)])
        self.assertEqual(len(selected["requests"]), 1)
        self.assertEqual(selected["requests"][0]["origin_run_ids"], ["123"])
        self.assertEqual(len(selected["requests"][0]["duplicate_runs"]), 2)
        conflict = fork_sync.select_requests([run(), run(target=SHA_C, run_id=12)])
        self.assertEqual(conflict["conflicts"], ["123"])
        self.assertEqual(conflict["requests"], [])

    def test_different_origins_for_same_target_are_coalesced(self):
        selected = fork_sync.select_requests(
            [run(origin="123"), run(origin="456", run_id=11)]
        )
        self.assertEqual(len(selected["requests"]), 1)
        self.assertEqual(selected["requests"][0]["origin_run_ids"], ["123", "456"])

    def test_comparison_requires_exact_merge_base(self):
        valid = {"status": "ahead", "merge_base_commit": {"sha": SHA_A}}
        rewritten = {"status": "ahead", "merge_base_commit": {"sha": SHA_B}}
        self.assertTrue(fork_sync.ancestry_proven(valid, SHA_A))
        self.assertFalse(fork_sync.ancestry_proven(rewritten, SHA_A))

    def test_later_merged_pr_can_contain_older_daily_target(self):
        later = pr(target=SHA_C, merged_at="2026-11-20T11:00:00Z", head_sha=SHA_C)
        later["target_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_A},
        }
        later["merge_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_A},
        }
        later["head_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_C},
        }
        later["fork_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_C},
        }
        result = fork_sync.continuation_target(
            {"target_sha": SHA_A}, [later], fork_main_sha=SHA_B
        )
        self.assertEqual(result["target_sha"], SHA_A)
        self.assertEqual(result["pr_target_sha"], SHA_C)

    def test_squashed_or_rebased_merge_is_not_accepted(self):
        rewritten = pr(target=SHA_C, merged_at="2026-11-20T11:00:00Z", head_sha=SHA_C)
        rewritten["target_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_A},
        }
        rewritten["merge_comparison"] = {
            "status": "diverged",
            "merge_base_commit": {"sha": SHA_B},
        }
        rewritten["head_comparison"] = {
            "status": "diverged",
            "merge_base_commit": {"sha": SHA_B},
        }
        rewritten["fork_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_C},
        }
        self.assertIsNone(
            fork_sync.continuation_target({"target_sha": SHA_A}, [rewritten], SHA_B)
        )

    def test_rewritten_pr_head_is_not_accepted_even_when_old_target_is_contained(self):
        rewritten = pr(target=SHA_C, merged_at="2026-11-20T11:00:00Z", head_sha=SHA_C)
        rewritten["target_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_A},
        }
        rewritten["merge_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_A},
        }
        rewritten["head_comparison"] = {
            "status": "diverged",
            "merge_base_commit": {"sha": SHA_B},
        }
        rewritten["fork_comparison"] = {
            "status": "ahead",
            "merge_base_commit": {"sha": SHA_C},
        }
        self.assertIsNone(
            fork_sync.continuation_target({"target_sha": SHA_A}, [rewritten], SHA_B)
        )

    def test_status_comment_is_bounded_idempotent_and_ambiguous_dispatch_burns(self):
        state = {
            "schema_version": 1,
            "pr_number": 4,
            "target_sha": SHA_C,
            "base_sha": SHA_B,
            "stage": "awaiting-human-merge",
            "continuations": [],
        }
        encoded = fork_sync.render_status_comment(state)
        self.assertEqual(fork_sync.parse_status_comment(encoded), state)
        reserved, status = fork_sync.reserve_continuation(state, SHA_A, ["123", "456"])
        self.assertEqual(status, "reserved")
        repeated, status = fork_sync.reserve_continuation(reserved, SHA_A, ["789"])
        self.assertEqual(status, "already-reserved")
        self.assertEqual(repeated, reserved)
        burned = fork_sync.set_dispatch_result(reserved, SHA_A, None)
        self.assertEqual(burned["continuations"][0]["stage"], "ambiguous")
        self.assertEqual(
            fork_sync.reserve_continuation(burned, SHA_A, ["123"])[1],
            "already-reserved",
        )

    def test_ledger_full_fails_closed(self):
        state = {
            "schema_version": 1,
            "pr_number": 1,
            "target_sha": SHA_C,
            "base_sha": SHA_B,
            "continuations": [
                {"target_sha": f"{index:040x}", "stage": "dispatched"}
                for index in range(fork_sync.MAX_CONTINUATIONS)
            ],
        }
        with self.assertRaises(fork_sync.ForkSyncError):
            fork_sync.reserve_continuation(state, SHA_A, ["123"])


class ForkWorkflowContractTests(unittest.TestCase):
    root = Path(__file__).parents[3]

    def test_fork_sync_never_updates_main_and_is_gated(self):
        workflow = (self.root / ".github/workflows/bot_sync-obi-fork.yml").read_text()
        self.assertNotIn("merge-upstream", workflow)
        self.assertIn("OBI_FORK_SYNC_WRITER_ENABLED == 'true'", workflow)
        self.assertIn("group: obi-adoption-writer", workflow)
        self.assertIn("inputs.obi_sha", workflow)
        self.assertIn("obi_fork_sync.py publish", workflow)

    def test_daily_adoption_requests_exact_sha_only_when_both_writers_enabled(self):
        workflow = (
            self.root / ".github/workflows/bot_sync-obi-submodule.yml"
        ).read_text()
        self.assertIn("inputs.request_run_id", workflow)
        self.assertIn("outputs.fork_relation == 'behind'", workflow)
        self.assertIn("outputs.fork_relation == 'diverged'", workflow)
        self.assertIn("inputs.request_run_id == ''", workflow)
        self.assertIn("vars.OBI_ADOPTION_WRITER_ENABLED == 'true'", workflow)
        self.assertIn("vars.OBI_FORK_SYNC_WRITER_ENABLED == 'true'", workflow)
        self.assertIn("obi_fork_sync.py request", workflow)

    def test_reusable_workflow_ref_fix_remains_local(self):
        supervisor = (
            self.root / ".github/workflows/supervisor_rerun-flaky.yml"
        ).read_text()
        match = re.search(
            r"(?ms)^  managed-adoption-repair:\n(.*?)(?=^  [\w-]+:\s*$|\Z)",
            supervisor,
        )
        self.assertIsNotNone(match)
        self.assertIn(
            "uses: ./.github/workflows/obi-adoption-repair.yml", match.group(1)
        )


if __name__ == "__main__":
    unittest.main()
