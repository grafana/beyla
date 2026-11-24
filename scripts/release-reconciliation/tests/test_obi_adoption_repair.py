import base64
import hashlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "adoption"))
import obi_adoption_repair as repair

TARGET = "b" * 40
BASE = "c" * 40
HEAD = "a" * 40
OLD_BLOB = "d" * 40
NEW_HEAD = "e" * 40
DIGEST = "f" * 64


def status_state():
    state = {
        "schema_version": 1,
        "pr_number": 123,
        "target_sha": TARGET,
        "base_sha": BASE,
        "head_sha": HEAD,
        "stage": "repairing",
        "repair_budget": {"used": 1, "max": 2},
        "reservation": {"attempt": 1, "digest": None},
        "deadline_utc": "2026-11-19T12:00:00Z",
        "required_checks": [],
    }
    state["reservation"]["digest"] = repair.state_digest(state)
    return state


def manifest(changes=None):
    return {
        "schema_version": 1,
        "pr_number": 123,
        "target_sha": TARGET,
        "base_sha": BASE,
        "expected_head_sha": HEAD,
        "trigger_run_id": 7,
        "attempt": 1,
        "max_attempts": 2,
        "reservation_digest": status_state()["reservation"]["digest"],
        "changes": changes
        or [
            {
                "path": "pkg/foo/foo.go",
                "base_blob_sha": OLD_BLOB,
                "base_mode": "100644",
                "mode": "100644",
                "new_text": "package foo\n",
            }
        ],
    }


class FakeGitHub(repair.GitHub):
    def __init__(self, *, verified=True, stale=False):
        super().__init__("grafana/beyla", "read-token", write_token="write-token")
        self.verified = verified
        self.stale = stale
        self.calls = []
        self._tree_cache[HEAD] = {
            "pkg/foo/foo.go": {"type": "blob", "mode": "100644", "sha": OLD_BLOB}
        }

    def pr(self, number):
        return {
            "number": number,
            "state": "open",
            "draft": True,
            "base": {"ref": "main", "sha": BASE},
            "head": {
                "ref": repair.managed_branch(TARGET),
                "sha": HEAD,
                "repo": {"full_name": "grafana/beyla"},
            },
            "user": {"login": "grafana-beyla-bot[bot]"},
            "body": f"<!-- grafana-beyla-obi-adoption:v1 target={TARGET} base={BASE} -->",
        }

    def request(self, method, path, body=None, *, write=False):
        self.calls.append((method, path, body, write))
        if path == "/commits/main":
            return {"sha": "0" * 40 if self.stale else BASE}
        if path.startswith("/contents/.obi-src?"):
            return {"type": "submodule", "sha": TARGET}
        if path.startswith("/contents/pkg/foo/foo.go?"):
            return {"type": "file", "sha": OLD_BLOB}
        if path.startswith("/issues/123/comments"):
            body_text = repair.encode_state_comment(status_state(), "current status")
            return [
                {
                    "body": body_text,
                    "user": {
                        "type": "Bot",
                        "login": "github-actions[bot]",
                        "id": 41898282,
                    },
                }
            ]
        if path == "/actions/runs/7":
            return {
                "event": "pull_request",
                "status": "completed",
                "conclusion": "failure",
                "head_sha": HEAD,
                "head_repository": {"full_name": "grafana/beyla"},
                "pull_requests": [{"number": 123}],
            }
        if path == "/git/commits/" + HEAD:
            return {"tree": {"sha": "1" * 40}}
        if path == "/git/ref/heads/" + repair.managed_branch(TARGET):
            return {"object": {"sha": HEAD}}
        if method == "POST" and path == "/git/blobs":
            return {"sha": "2" * 40}
        if method == "POST" and path == "/git/trees":
            return {"sha": "3" * 40, "truncated": False}
        if method == "POST" and path == "/git/commits":
            return {"sha": NEW_HEAD, "verification": {"verified": self.verified}}
        if method == "PATCH":
            return {"object": {"sha": NEW_HEAD}}
        raise AssertionError((method, path, body, write))


class ReservationTests(unittest.TestCase):
    def test_canonical_comment_round_trip(self):
        state = status_state()
        body = repair.encode_state_comment(state, "hello")
        self.assertEqual(state, repair.extract_state_comment(body))
        repair.validate_reservation(
            state,
            pr_number=123,
            target_sha=TARGET,
            base_sha=BASE,
            head_sha=HEAD,
            attempt=1,
            max_attempts=2,
            reservation_digest=state["reservation"]["digest"],
        )

    def test_duplicate_or_noncanonical_state_fails(self):
        body = repair.encode_state_comment(status_state())
        with self.assertRaises(repair.RepairError):
            repair.extract_state_comment(body + body)
        token = base64.urlsafe_b64encode(b'{ "a": 1 }').decode().rstrip("=")
        with self.assertRaises(repair.RepairError):
            repair.extract_state_comment(
                f"{repair.STATUS_MARKER}\n<!-- obi-adoption-state:v1:{token} -->"
            )


class FailedJobLogTests(unittest.TestCase):
    def test_plain_job_log_text_extracts_failure_and_scrubs_token(self):
        log = (
            b"2026-11-19T12:00:00Z setup complete\n"
            b"2026-11-19T12:00:01Z go test ./pkg/foo\n"
            b"2026-11-19T12:00:02Z token=ghp_abcdefghijklmnopqrstuvwxyz012345\n"
            b"2026-11-19T12:00:03Z ##[error] FAIL: TestExample\n"
        )
        excerpt = repair.excerpts_from_log(log)
        self.assertTrue(any("FAIL: TestExample" in line for line in excerpt))
        self.assertTrue(any("[REDACTED]" in line for line in excerpt))
        self.assertFalse(
            any("ghp_abcdefghijklmnopqrstuvwxyz012345" in line for line in excerpt)
        )

    def test_plain_job_log_size_is_bounded(self):
        with self.assertRaises(repair.RepairError):
            repair.excerpts_from_log(b"x" * (repair.MAX_LOG_BYTES + 1))

    def test_log_redirect_does_not_forward_api_authorization(self):
        class RedirectingOpener:
            def open(self, request, timeout):
                self.request = request
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "redirect",
                    {"Location": "https://logs.actions.githubusercontent.com/signed"},
                    None,
                )

        opener = RedirectingOpener()
        signed_response = io.BytesIO(b"plain job log")
        with (
            patch.object(repair.urllib.request, "build_opener", return_value=opener),
            patch.object(
                repair.urllib.request, "urlopen", return_value=signed_response
            ) as redirected,
        ):
            result = repair.GitHub("grafana/beyla", "api-secret").request_bytes(
                "/actions/jobs/1/logs"
            )
        self.assertEqual(result, b"plain job log")
        redirected_request = redirected.call_args.args[0]
        self.assertNotIn("Authorization", redirected_request.headers)
        self.assertEqual(
            opener.request.get_header("Authorization"), "Bearer api-secret"
        )

    def test_production_actions_blob_redirect_is_allowed_without_auth(self):
        class RedirectingOpener:
            def open(self, request, timeout):
                self.request = request
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "redirect",
                    {
                        "Location": "https://productionresultssa0.blob.core.windows.net/logs/signed?sig=private"
                    },
                    None,
                )

        opener = RedirectingOpener()
        with (
            patch.object(repair.urllib.request, "build_opener", return_value=opener),
            patch.object(
                repair.urllib.request, "urlopen", return_value=io.BytesIO(b"logs")
            ) as redirected,
        ):
            self.assertEqual(
                repair.GitHub("grafana/beyla", "api-secret").request_bytes(
                    "/actions/jobs/1/logs"
                ),
                b"logs",
            )
        self.assertNotIn("Authorization", redirected.call_args.args[0].headers)

    def test_lookalike_blob_redirect_host_is_rejected(self):
        class RedirectingOpener:
            def open(self, request, timeout):
                raise urllib.error.HTTPError(
                    request.full_url,
                    302,
                    "redirect",
                    {
                        "Location": "https://productionresultssa0.blob.core.windows.net.attacker.example/logs"
                    },
                    None,
                )

        with (
            patch.object(
                repair.urllib.request, "build_opener", return_value=RedirectingOpener()
            ),
            self.assertRaises(repair.RepairError),
        ):
            repair.GitHub("grafana/beyla", "api-secret").request_bytes(
                "/actions/jobs/1/logs"
            )


class WorkflowContractTests(unittest.TestCase):
    def test_cli_repair_gate_requires_both_variables(self):
        for writer, repair_enabled in (
            (None, "true"),
            ("true", None),
            ("true", "false"),
        ):
            with (
                self.subTest(writer=writer, repair=repair_enabled),
                patch.dict(
                    os.environ,
                    {
                        "OBI_ADOPTION_WRITER_ENABLED": writer or "",
                        "OBI_ADOPTION_REPAIR_ENABLED": repair_enabled or "",
                    },
                ),
                self.assertRaises(repair.RepairError),
            ):
                repair.require_repair_enabled()
        with patch.dict(
            os.environ,
            {
                "OBI_ADOPTION_WRITER_ENABLED": "true",
                "OBI_ADOPTION_REPAIR_ENABLED": "true",
            },
        ):
            repair.require_repair_enabled()

    def test_repair_workflow_is_double_gated_and_prepares_candidate(self):
        workflow = (
            Path(__file__).parents[3] / ".github/workflows/obi-adoption-repair.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(
            workflow.count("vars.OBI_ADOPTION_WRITER_ENABLED == 'true'"), 4
        )
        self.assertGreaterEqual(
            workflow.count("vars.OBI_ADOPTION_REPAIR_ENABLED == 'true'"), 4
        )
        self.assertIn("submodules: recursive", workflow)
        self.assertIn("mise run vendor:obi", workflow)
        self.assertLess(
            workflow.index("name: Prepare generated OBI bindings"),
            workflow.index("name: Run formatting and targeted Go tests"),
        )

    def test_wrong_actor_and_digest_fail(self):
        github = FakeGitHub()
        original = github.request

        def forged(method, path, body=None, *, write=False):
            value = original(method, path, body, write=write)
            if path.startswith("/issues/"):
                value[0]["user"]["login"] = "other-bot[bot]"
            return value

        github.request = forged
        with self.assertRaises(repair.RepairError):
            repair.verify_status_reservation(
                github,
                pr_number=123,
                target_sha=TARGET,
                base_sha=BASE,
                head_sha=HEAD,
                attempt=1,
                max_attempts=2,
                reservation_digest=status_state()["reservation"]["digest"],
            )
        with self.assertRaises(repair.RepairError):
            repair.validate_reservation(
                status_state(),
                pr_number=123,
                target_sha=TARGET,
                base_sha=BASE,
                head_sha=HEAD,
                attempt=2,
                max_attempts=2,
                reservation_digest=DIGEST,
            )

    def test_only_trusted_supervisor_workflow_run_can_call_worker(self):
        repair.validate_caller(
            "grafana/beyla",
            "workflow_run",
            "grafana/beyla/.github/workflows/supervisor_rerun-flaky.yml@refs/heads/main",
        )
        for repo, event, ref in (
            (
                "other/beyla",
                "workflow_run",
                "grafana/beyla/.github/workflows/supervisor_rerun-flaky.yml@refs/heads/main",
            ),
            (
                "grafana/beyla",
                "workflow_dispatch",
                "grafana/beyla/.github/workflows/supervisor_rerun-flaky.yml@refs/heads/main",
            ),
            (
                "grafana/beyla",
                "workflow_run",
                "grafana/beyla/.github/workflows/supervisor_rerun-flaky.yml@refs/heads/topic",
            ),
        ):
            with (
                self.subTest(repo=repo, event=event, ref=ref),
                self.assertRaises(repair.RepairError),
            ):
                repair.validate_caller(repo, event, ref)


class ManifestTests(unittest.TestCase):
    def test_rejects_path_traversal_vendor_gitlink_executable_and_oversize(self):
        for path in (
            "../pkg/foo.go",
            "pkg/../foo.go",
            "vendor/evil.go",
            ".obi-src",
            "pkg/evil;echo.go",
        ):
            with self.subTest(path=path):
                self.assertFalse(repair.allowed_path(path))
        for change in (
            {
                "path": "pkg/foo/foo.go",
                "base_blob_sha": OLD_BLOB,
                "base_mode": "100644",
                "mode": "120000",
                "new_text": "x",
            },
            {
                "path": "pkg/foo/foo.go",
                "base_blob_sha": OLD_BLOB,
                "base_mode": "100755",
                "mode": "100644",
                "new_text": "x",
            },
            {
                "path": "pkg/foo/foo.go",
                "base_blob_sha": OLD_BLOB,
                "base_mode": "100644",
                "mode": "100644",
                "new_text": "x" * 32_001,
            },
        ):
            with self.subTest(change=change), self.assertRaises(repair.RepairError):
                repair.validate_manifest(
                    {**manifest([change])},
                    pr_number=123,
                    target_sha=TARGET,
                    base_sha=BASE,
                    head_sha=HEAD,
                    reservation_digest=status_state()["reservation"]["digest"],
                )

    def test_manifest_identity_is_bound(self):
        value = manifest()
        repair.validate_manifest(
            value,
            pr_number=123,
            target_sha=TARGET,
            base_sha=BASE,
            head_sha=HEAD,
            reservation_digest=value["reservation_digest"],
        )
        with self.assertRaises(repair.RepairError):
            repair.validate_manifest(
                value,
                pr_number=123,
                target_sha="9" * 40,
                base_sha=BASE,
                head_sha=HEAD,
                reservation_digest=value["reservation_digest"],
            )

    def test_apply_requires_exact_head_gitlink_and_regular_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "test"], check=True
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
            )
            path = root / "pkg/foo/foo.go"
            path.parent.mkdir(parents=True)
            original = b"package foo\n"
            path.write_bytes(original)
            os.chmod(path, 0o644)
            subprocess.run(
                ["git", "-C", str(root), "add", "pkg/foo/foo.go"], check=True
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    f"160000,{TARGET},.obi-src",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "commit", "-m", "base"],
                check=True,
                capture_output=True,
            )
            head = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            value = manifest()
            value["expected_head_sha"] = head
            value["changes"][0]["base_blob_sha"] = repair.git_blob_sha(original)
            packages = repair.apply_manifest(value, str(root))
            self.assertEqual(["./pkg/foo"], packages)
            self.assertEqual("package foo\n", path.read_text())


class PublisherTests(unittest.TestCase):
    def test_publish_rechecks_and_nonforce_updates_after_verified_commit(self):
        gh = FakeGitHub()
        data = manifest()
        digest = hashlib.sha256(repair.canonical_json(data)).hexdigest()
        result = repair.publish_repair(
            gh,
            data,
            pr_number=123,
            target_sha=TARGET,
            base_sha=BASE,
            head_sha=HEAD,
            attempt=1,
            max_attempts=2,
            reservation_digest=status_state()["reservation"]["digest"],
            trigger_run_id=7,
            manifest_sha256=digest,
        )
        self.assertEqual(NEW_HEAD, result["new_head_sha"])
        self.assertIn(
            (
                "PATCH",
                f"/git/refs/heads/{repair.managed_branch(TARGET)}",
                {"sha": NEW_HEAD, "force": False},
                True,
            ),
            gh.calls,
        )

    def test_stale_main_or_unverified_commit_never_moves_branch(self):
        for gh in (FakeGitHub(stale=True), FakeGitHub(verified=False)):
            with self.subTest(stale=gh.stale, verified=gh.verified):
                data = manifest()
                with self.assertRaises(repair.RepairError):
                    repair.publish_repair(
                        gh,
                        data,
                        pr_number=123,
                        target_sha=TARGET,
                        base_sha=BASE,
                        head_sha=HEAD,
                        attempt=1,
                        max_attempts=2,
                        reservation_digest=status_state()["reservation"]["digest"],
                        trigger_run_id=7,
                        manifest_sha256=hashlib.sha256(
                            repair.canonical_json(data)
                        ).hexdigest(),
                    )
                self.assertFalse(any(method == "PATCH" for method, *_ in gh.calls))

    def test_foreign_or_stale_pr_fails_before_git_write(self):
        gh = FakeGitHub()
        original = gh.pr
        gh.pr = lambda number: {
            **original(number),
            "head": {**original(number)["head"], "sha": "9" * 40},
        }
        data = manifest()
        with self.assertRaises(repair.RepairError):
            repair.publish_repair(
                gh,
                data,
                pr_number=123,
                target_sha=TARGET,
                base_sha=BASE,
                head_sha=HEAD,
                attempt=1,
                max_attempts=2,
                reservation_digest=status_state()["reservation"]["digest"],
                trigger_run_id=7,
                manifest_sha256=hashlib.sha256(repair.canonical_json(data)).hexdigest(),
            )
        self.assertFalse(any(method == "POST" for method, *_ in gh.calls))


if __name__ == "__main__":
    unittest.main()
