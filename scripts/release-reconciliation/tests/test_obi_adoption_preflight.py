import importlib.util
import unittest
from pathlib import Path

path = Path(__file__).parents[1] / "adoption" / "preflight" / "reconcile.py"
spec = importlib.util.spec_from_file_location("reconcile", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReconcileTests(unittest.TestCase):
    def facts(self):
        return {
            "run": {
                "run_id": "1",
                "attempt": "1",
                "ref": "refs/heads/main",
                "head_sha": "a" * 40,
            },
            "source": {
                "upstream_sha": "b" * 40,
                "pin_sha": "a" * 40,
                "graph_complete": True,
                "snapshot_current_main": True,
                "pin_is_ancestor": True,
                "upstream_is_ancestor_of_pin": False,
                "pending_count": 0,
                "timestamps_valid": True,
            },
            "active_prs": [],
            "open_pr_inventory_complete": True,
            "closed_target_history_complete": True,
        }

    def test_noop_is_distinct(self):
        facts = self.facts()
        facts["source"]["upstream_sha"] = facts["source"]["pin_sha"]
        result = module.reconcile(facts, "2026-11-19T12:00:00Z")
        self.assertEqual("no-op", result["adoption"]["outcome"])
        self.assertEqual("fresh", result["pending"]["freshness"])

    def test_stale_workflow_noop_is_unknown(self):
        facts = self.facts()
        facts["source"].update(
            upstream_sha="a" * 40, pin_sha="a" * 40, snapshot_current_main=False
        )
        self.assertEqual(
            "unknown",
            module.reconcile(facts, "2026-11-19T12:00:00Z")["adoption"]["outcome"],
        )

    def test_noop_does_not_depend_on_pr_inventory(self):
        facts = self.facts()
        facts["source"].update(
            upstream_sha="a" * 40, pin_sha="a" * 40, pending_count=0
        )
        facts["open_pr_inventory_complete"] = False
        self.assertEqual(
            "no-op",
            module.reconcile(facts, "2026-11-19T12:00:00Z")["adoption"]["outcome"],
        )

    def test_noop_with_open_adoption_pr_reports_active_hold(self):
        facts = self.facts()
        facts["source"]["upstream_sha"] = facts["source"]["pin_sha"]
        facts["active_prs"] = [{"number": 9}]
        result = module.reconcile(facts, "2026-11-19T12:00:00Z")
        self.assertEqual("active", result["adoption"]["outcome"])
        self.assertIn("human disposition", result["adoption"]["next_action"])

    def test_current_pin_newer_than_sampled_upstream_is_superseded(self):
        facts = self.facts()
        facts["source"].update(graph_complete=True, upstream_is_ancestor_of_pin=True)
        self.assertEqual(
            "superseded",
            module.reconcile(facts, "2026-11-19T12:00:00Z")["adoption"]["outcome"],
        )

    def test_active_pr_preserved_without_retarget(self):
        facts = self.facts()
        facts["active_prs"] = [{"number": 1, "target_sha": "d" * 40}]
        self.assertEqual(
            "active",
            module.reconcile(facts, "2026-11-19T12:00:00Z")["adoption"]["outcome"],
        )

    def test_stale_age_is_not_adoption_blocker(self):
        facts = self.facts()
        facts["source"].update(
            pending_count=1,
            oldest_sha="d" * 40,
            oldest_committer_at="2026-11-18T00:00:00Z",
        )
        result = module.reconcile(facts, "2026-11-19T00:00:00Z")
        self.assertEqual("stale", result["pending"]["freshness"])
        self.assertEqual("source-candidate", result["adoption"]["outcome"])

    def test_unparseable_non_oldest_commit_makes_proxy_unknown(self):
        facts = self.facts()
        facts["source"].update(
            pending_count=2,
            oldest_sha="d" * 40,
            oldest_committer_at="2026-11-18T00:00:00Z",
            timestamps_valid=False,
        )
        self.assertEqual(
            "unknown",
            module.reconcile(facts, "2026-11-19T00:00:00Z")["pending"]["freshness"],
        )

    def test_age_at_threshold_is_stale(self):
        facts = self.facts()
        facts["source"].update(
            pending_count=1,
            oldest_sha="d" * 40,
            oldest_committer_at="2026-11-18T00:00:00Z",
        )
        result = module.reconcile(facts, "2026-11-19T00:00:00Z")
        self.assertEqual("stale", result["pending"]["freshness"])

    def test_future_age_unknown_not_blocking(self):
        facts = self.facts()
        facts["source"].update(
            pending_count=1,
            oldest_sha="d" * 40,
            oldest_committer_at="2026-11-20T00:00:00Z",
        )
        result = module.reconcile(facts, "2026-11-19T00:00:00Z")
        self.assertEqual("unknown", result["pending"]["freshness"])

    def test_incomplete_graph_fails_closed(self):
        facts = self.facts()
        facts["source"]["graph_complete"] = False
        self.assertEqual(
            "unknown",
            module.reconcile(facts, "2026-11-19T12:00:00Z")["adoption"]["outcome"],
        )

    def test_rejected_requires_human_retry(self):
        facts = self.facts()
        facts["rejected_exact_target"] = True
        result = module.reconcile(facts, "2026-11-19T12:00:00Z")
        self.assertEqual("rejected", result["adoption"]["outcome"])
        self.assertIn("authorization", result["adoption"]["next_action"])

    def test_collection_error_overrides_apparently_complete_partial_facts(self):
        facts = self.facts()
        facts["collection_error"] = "mock request failed"
        result = module.reconcile(facts, "2026-11-19T12:00:00Z")
        self.assertEqual("unknown", result["adoption"]["outcome"])
        self.assertIn("partial facts", result["adoption"]["blocker"])

    def test_unknown_open_pr_inventory_fails_closed(self):
        facts = self.facts()
        facts["open_pr_inventory_complete"] = False
        self.assertEqual(
            "unknown",
            module.reconcile(facts, "2026-11-19T12:00:00Z")["adoption"]["outcome"],
        )

    def test_bounded_closed_history_does_not_claim_eligibility(self):
        facts = self.facts()
        facts["closed_target_history_complete"] = False
        result = module.reconcile(facts, "2026-11-19T12:00:00Z")
        self.assertEqual("source-candidate", result["adoption"]["outcome"])
        self.assertIn("bounded", result["adoption"]["blocker"])


class CollectorHelperTests(unittest.TestCase):
    def test_api_failure_mid_scan_invalidates_partial_inventory(self):
        import sys
        from unittest.mock import patch

        script_dir = str(Path(__file__).parents[1] / "adoption" / "preflight")
        sys.path.insert(0, script_dir)
        try:
            import collect

            facts = {
                "active_prs": [],
                "rejected_exact_target": False,
                "open_pr_inventory_complete": True,
                "closed_target_history_complete": True,
            }
            open_pr = {"number": 7, "state": "open", "changed_files": 1}
            with (
                patch.object(
                    collect,
                    "api",
                    side_effect=[
                        [open_pr],
                        [],
                        RuntimeError("mock managed history failure"),
                    ],
                ),
                patch.object(
                    collect,
                    "search_issues",
                    side_effect=AssertionError(
                        "legacy search must not run after API failure"
                    ),
                ),
                self.assertRaises(RuntimeError),
            ):
                collect.collect_pr_inventory(facts, "b" * 40)
            self.assertFalse(facts["open_pr_inventory_complete"])
            self.assertFalse(facts["closed_target_history_complete"])
        finally:
            sys.path.remove(script_dir)
            sys.modules.pop("collect", None)

    def test_closed_managed_branch_exact_target_is_rejected(self):
        import sys
        from unittest.mock import patch

        script_dir = str(Path(__file__).parents[1] / "adoption" / "preflight")
        sys.path.insert(0, script_dir)
        try:
            import collect

            sha = "b" * 40
            closed_pr = {
                "number": 12,
                "state": "closed",
                "changed_files": 1,
                "body": f"<!-- grafana-beyla-obi-adoption:v1 target={sha} base={'a' * 40} -->",
                "head": {"sha": "c" * 40},
            }
            facts = {
                "active_prs": [],
                "rejected_exact_target": False,
                "open_pr_inventory_complete": True,
                "closed_target_history_complete": True,
            }
            with (
                patch.object(
                    collect,
                    "api",
                    side_effect=[[], [closed_pr], [{"filename": ".obi-src"}]],
                ),
                patch.object(collect, "target_for", return_value=sha),
                patch.object(
                    collect,
                    "search_issues",
                    return_value={"items": [], "total_count": 0},
                ),
            ):
                collect.collect_pr_inventory(facts, sha)
            self.assertTrue(facts["closed_exact_target"])
            self.assertTrue(facts["rejected_exact_target"])
            self.assertTrue(facts["closed_target_history_complete"])
        finally:
            sys.path.remove(script_dir)
            sys.modules.pop("collect", None)

    def test_legacy_issue_search_uses_get_and_checks_completeness(self):
        import sys
        from unittest.mock import patch

        script_dir = str(Path(__file__).parents[1] / "adoption" / "preflight")
        sys.path.insert(0, script_dir)
        try:
            import collect

            with patch.object(
                collect,
                "cmd",
                return_value='{"items":[],"total_count":0,"incomplete_results":false}',
            ) as command:
                self.assertFalse(
                    collect.search_issues(
                        "repo:grafana/beyla is:pr is:closed " + "a" * 40
                    )["incomplete_results"]
                )
            args = command.call_args.args[0]
            self.assertEqual("GET", args[args.index("--method") + 1])
        finally:
            sys.path.remove(script_dir)
            sys.modules.pop("collect", None)

    def test_noop_still_reads_open_prs_without_closed_history_scans(self):
        import io
        import sys
        from contextlib import redirect_stdout
        from unittest.mock import call, patch

        script_dir = str(Path(__file__).parents[1] / "adoption" / "preflight")
        sys.path.insert(0, script_dir)
        try:
            import collect

            sha = "a" * 40

            def command(args, timeout=30):
                if args[:2] == ["git", "ls-tree"]:
                    return f"160000 commit {sha} .obi-src"
                if args[:3] == ["gh", "api", f"repos/{collect.REPO}/commits/main"]:
                    return sha
                raise AssertionError(f"unexpected no-op command: {args}")

            output = io.StringIO()
            with (
                patch.dict(
                    "os.environ",
                    {
                        "GITHUB_REF": "refs/heads/main",
                        "GITHUB_SHA": sha,
                        "GITHUB_RUN_ID": "1",
                        "GITHUB_RUN_ATTEMPT": "1",
                        "OBI_SHA": sha,
                    },
                    clear=True,
                ),
                patch.object(collect, "cmd", side_effect=command),
                patch.object(collect, "api", return_value=[]) as api_call,
                redirect_stdout(output),
            ):
                collect.main()
            self.assertEqual(
                [
                    call(
                        f"repos/{collect.REPO}/pulls?state=open&base=main&per_page=100&page=1"
                    )
                ],
                api_call.call_args_list,
            )
            self.assertIn('"outcome": "no-op"', output.getvalue())
        finally:
            sys.path.remove(script_dir)
            sys.modules.pop("collect", None)

    def test_ancestry_helper_uses_local_git_without_network(self):
        import io
        import subprocess
        import sys
        import tempfile
        from contextlib import redirect_stdout
        from unittest.mock import patch

        script_dir = str(Path(__file__).parents[1] / "adoption" / "preflight")
        sys.path.insert(0, script_dir)
        try:
            import collect

            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run(["git", "init", tmp], check=True, capture_output=True)
                subprocess.run(
                    ["git", "-C", tmp, "config", "user.name", "Test"], check=True
                )
                subprocess.run(
                    ["git", "-C", tmp, "config", "user.email", "test@example.invalid"],
                    check=True,
                )
                Path(tmp, "file").write_text("one")
                subprocess.run(["git", "-C", tmp, "add", "file"], check=True)
                subprocess.run(
                    ["git", "-C", tmp, "commit", "-m", "one"],
                    check=True,
                    capture_output=True,
                )
                first = subprocess.run(
                    ["git", "-C", tmp, "rev-parse", "HEAD"],
                    check=True,
                    text=True,
                    capture_output=True,
                ).stdout.strip()
                Path(tmp, "file").write_text("two")
                subprocess.run(
                    ["git", "-C", tmp, "commit", "-am", "two"],
                    check=True,
                    capture_output=True,
                )
                second = subprocess.run(
                    ["git", "-C", tmp, "rev-parse", "HEAD"],
                    check=True,
                    text=True,
                    capture_output=True,
                ).stdout.strip()
                self.assertTrue(collect.is_ancestor(tmp, first, second))
                self.assertFalse(collect.is_ancestor(tmp, second, first))
            with patch.object(
                collect, "cmd", return_value='[{"number":1},{"number":2}]'
            ):
                self.assertEqual([{"number": 1}, {"number": 2}], collect.api("unused"))
            output = io.StringIO()
            with (
                patch.dict(
                    "os.environ",
                    {"GITHUB_REF": "refs/pull/1/merge", "GITHUB_SHA": "a" * 40},
                    clear=True,
                ),
                redirect_stdout(output),
            ):
                collect.main()
            self.assertIn('"outcome": "unknown"', output.getvalue())
            self.assertNotIn("token", output.getvalue().lower())
        finally:
            sys.path.remove(script_dir)
            sys.modules.pop("collect", None)


class PublishPlanTests(unittest.TestCase):
    def report(self):
        return {
            "collection_error": None,
            "source": {
                "upstream_sha": "b" * 40,
                "pin_sha": "a" * 40,
                "main_head_sha": "c" * 40,
                "snapshot_current_main": True,
            },
            "pending": {"freshness": "stale"},
            "inventory": {
                "open_pr_complete": True,
                "closed_target_history_complete": True,
            },
            "adoption": {
                "outcome": "source-candidate",
                "active_prs": [],
                "blocker": None,
            },
        }

    def module(self):
        import sys

        path = str(Path(__file__).parents[1] / "adoption" / "preflight")
        sys.path.insert(0, path)
        try:
            import plan

            return plan
        finally:
            sys.path.remove(path)
            sys.modules.pop("plan", None)

    def test_new_candidate_does_not_block_on_stale_or_unknown_age_proxy(self):
        module = self.module()
        report = self.report()
        self.assertEqual("create", module.publish_plan(report)["action"])
        report["pending"]["freshness"] = "unknown"
        self.assertEqual("create", module.publish_plan(report)["action"])

    def test_existing_a_is_preserved_when_latest_b_arrives(self):
        module = self.module()
        report = self.report()
        report["adoption"].update(
            outcome="active",
            active_prs=[
                {
                    "number": 10,
                    "target_sha": "d" * 40,
                    "head_branch": "update-obi-adoption-" + "d" * 40,
                    "head_repo": "grafana/beyla",
                    "head_sha": "e" * 40,
                }
            ],
        )
        result = module.publish_plan(report)
        self.assertEqual("defer", result["action"])
        self.assertIn("different OBI SHA", result["reason"])

    def test_main_pin_noop_still_observes_exact_managed_pr_for_human_disposition(self):
        module = self.module()
        report = self.report()
        target = "b" * 40
        report["source"].update(upstream_sha=target, pin_sha=target)
        report["adoption"].update(
            outcome="active",
            active_prs=[
                {
                    "target_sha": target,
                    "head_branch": f"update-obi-adoption-{target}",
                    "head_repo": "grafana/beyla",
                    "managed_marker": True,
                    "number": 9,
                    "head_sha": "d" * 40,
                    "managed_base_sha": "a" * 40,
                }
            ],
        )
        action = module.publish_plan(report)
        self.assertEqual("superseded", action["action"])
        self.assertEqual(9, action["pr_number"])

    def test_only_exact_managed_pr_head_may_be_updated(self):
        module = self.module()
        report = self.report()
        target, base, head = (
            report["source"]["upstream_sha"],
            report["source"]["main_head_sha"],
            "d" * 40,
        )
        report["adoption"].update(
            outcome="active",
            active_prs=[
                {
                    "number": 11,
                    "target_sha": target,
                    "head_branch": "update-obi-adoption-" + target,
                    "head_repo": "grafana/beyla",
                    "head_sha": head,
                    "managed_marker": True,
                    "managed_base_sha": base,
                }
            ],
        )
        result = module.publish_plan(report)
        self.assertEqual("observe", result["action"])
        self.assertEqual(head, result["expected_pr_head"])
        report["adoption"]["active_prs"][0]["managed_marker"] = False
        self.assertEqual("defer", module.publish_plan(report)["action"])

    def test_incomplete_exact_target_history_blocks_new_sha_respawn(self):
        module = self.module()
        report = self.report()
        report["inventory"]["closed_target_history_complete"] = False
        result = module.publish_plan(report)
        self.assertEqual("blocked", result["action"])
        self.assertIn("history is incomplete", result["reason"])


if __name__ == "__main__":
    unittest.main()
