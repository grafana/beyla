import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("report", Path(__file__).with_name("report.py"))
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class ReportTests(unittest.TestCase):
    def facts(self, **overrides):
        facts = {"repository": "grafana/beyla", "candidate": {"sha": "a" * 40, "obi_sha": "b" * 40}, "runs": [], "releases": [], "beyla_refs": [], "obi_refs": [], "unavailable": []}
        facts.update(overrides)
        return facts

    def test_duplicate_facts_are_deterministic_and_no_version_is_selected(self):
        facts = self.facts()
        result = report.report(facts, "2026-11-16T12:00:00+00:00")
        self.assertEqual(result, report.report(facts, "2026-11-16T12:00:00+00:00"))
        self.assertIsNone(result["candidate"]["version"])

    def test_pipeline_bad_files_falls_back_to_typed_values_and_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            payloads = {"candidate.json": "{}", "obi.json": "{bad", "prepare-runs.json": "[]", "tag-runs.json": "{}", "releases.json": "[]", "beyla-refs.json": "[]", "obi-refs.json": "[]"}
            for name, raw in payloads.items():
                (Path(directory) / name).write_text(raw)
            facts = report.load_facts(directory, "grafana/beyla")
            self.assertIsInstance(facts["runs"], list)
            self.assertIsInstance(facts["releases"], list)
            self.assertEqual("unknown", report.report(facts)["state"])

    def test_active_prepare_or_tag_run_is_underway(self):
        self.assertEqual("underway", report.report(self.facts(runs=[{"status": "in_progress", "name": "prepare"}]))["state"])
        self.assertEqual("underway", report.report(self.facts(runs=[{"status": "queued", "name": "tag"}]))["state"])

    def test_historical_failure_superseded_by_success_is_not_blocking(self):
        runs = [
            {"workflow_id": 10, "head_branch": "release-v1", "run_number": 1, "created_at": "2026-11-01", "status": "completed", "conclusion": "failure"},
            {"workflow_id": 10, "head_branch": "release-v1", "run_number": 2, "created_at": "2026-11-02", "status": "completed", "conclusion": "success"},
        ]
        result = report.report(self.facts(runs=runs))
        self.assertEqual("candidate", result["state"])
        self.assertEqual(0, result["latest_failed_run_count"])

    def test_unrecognized_run_status_is_unknown(self):
        self.assertEqual("unknown", report.report(self.facts(runs=[{"status": "new-github-state"}]))["state"])

    def test_branch_asymmetry_is_diagnostic_not_active_train_proof(self):
        result = report.report(self.facts(beyla_refs=["release-v1"], obi_refs=[]))
        self.assertEqual("needs-review", result["state"])
        self.assertIn("not proof", result["next_step"])

    def test_missing_source_sha_and_unavailable_are_unknown(self):
        self.assertEqual("unknown", report.report(self.facts(candidate={"sha": "a" * 40}))["state"])
        self.assertEqual("unknown", report.report(self.facts(unavailable=["OBI fork"]))["state"])

    def test_paginated_payloads_are_flattened(self):
        with tempfile.TemporaryDirectory() as directory:
            payloads = {"candidate.json": json.dumps({"sha": "a" * 40}), "obi.json": json.dumps({"sha": "b" * 40}),
                        "prepare-runs.json": json.dumps([{"workflow_runs": [{"id": 1, "status": "completed"}]}]),
                        "tag-runs.json": json.dumps([{"workflow_runs": [{"id": 2, "status": "completed"}]}]),
                        "releases.json": json.dumps([[{"id": 1}], [{"id": 2}]]),
                        "beyla-refs.json": "[[]]", "obi-refs.json": "[[]]"}
            for name, raw in payloads.items():
                (Path(directory) / name).write_text(raw)
            facts = report.load_facts(directory, "grafana/beyla")
            self.assertEqual([1, 2], [run["id"] for run in facts["runs"]])
            self.assertEqual(2, len(facts["releases"]))
            self.assertFalse(facts["unavailable"])

    def test_weekly_publication_observation_and_policy_ambiguity(self):
        releases = [
            {"published_at": "2026-11-16T10:00:00Z", "prerelease": True},
            {"published_at": "2026-11-01T10:00:00Z", "prerelease": False},
        ]
        result = report.report(self.facts(releases=releases), "2026-11-16T12:00:00+00:00")
        self.assertTrue(result["new_publication_this_utc_week"])
        self.assertEqual("prerelease-only-needs-policy", result["weekly_cadence_observation"])
        self.assertIsNotNone(result["latest_stable_published_at"])
        self.assertIsNotNone(result["latest_prerelease_published_at"])

    def test_no_publication_this_utc_week_is_observation_not_gate(self):
        result = report.report(self.facts(releases=[{"published_at": "2026-11-01T10:00:00Z", "prerelease": False}]), "2026-11-16T12:00:00+00:00")
        self.assertFalse(result["new_publication_this_utc_week"])
        self.assertEqual("no-publication-observed", result["weekly_cadence_observation"])

    def test_future_release_excluded_and_naive_timestamp_unknown(self):
        future = {"published_at": "2026-11-20T10:00:00Z", "prerelease": False}
        result = report.report(self.facts(releases=[future]), "2026-11-16T12:00:00-05:00")
        self.assertFalse(result["new_publication_this_utc_week"])
        naive = {"published_at": "2026-11-16T10:00:00", "prerelease": False}
        self.assertEqual("unknown", report.report(self.facts(releases=[naive]))["state"])

    def test_cli_numeric_timestamp_reports_unknown(self):
        facts = self.facts(releases=[{"published_at": 7, "prerelease": False}])
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name("report.py"))], input=json.dumps(facts), text=True, capture_output=True, check=True)
        self.assertEqual("unknown", json.loads("\n".join(completed.stdout.splitlines()[1:-1]))["state"])

    def test_cli_wraps_one_json_report_in_stable_log_markers(self):
        completed = subprocess.run([sys.executable, str(Path(__file__).with_name("report.py"))], input=json.dumps(self.facts()), text=True, capture_output=True, check=True)
        lines = completed.stdout.splitlines()
        self.assertEqual("BEGIN_RELEASE_RECONCILIATION_REPORT", lines[0])
        self.assertEqual("END_RELEASE_RECONCILIATION_REPORT", lines[-1])
        payload = "\n".join(lines[1:-1])
        self.assertEqual(1, completed.stdout.count('"state"'))
        self.assertEqual("candidate", json.loads(payload)["state"])

    def test_workflow_logs_markers_around_report_without_unused_output(self):
        workflow = (Path(__file__).parents[2] / ".github/workflows/release-reconciliation.yml").read_text()
        begin = workflow.index('echo "BEGIN_RELEASE_RECONCILIATION_REPORT"')
        payload = workflow.index('cat "$facts_dir/report.json" | tee /tmp/release-report.json')
        end = workflow.index('echo "END_RELEASE_RECONCILIATION_REPORT"')
        self.assertLess(begin, payload)
        self.assertLess(payload, end)
        self.assertNotIn("GITHUB_OUTPUT", workflow)


if __name__ == "__main__":
    unittest.main()
