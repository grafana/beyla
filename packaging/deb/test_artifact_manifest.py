"""Offline tests for artifact_manifest.py."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("artifact_manifest.py")


class ArtifactManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.source), "config", "user.name", "Test"], check=True)
        (self.source / "tracked").write_text("initial\n")
        subprocess.run(["git", "-C", str(self.source), "add", "tracked"], check=True)
        subprocess.run(["git", "-C", str(self.source), "commit", "-qm", "fixture"], check=True)
        self.package = self.root / "beyla_1.2.3_amd64.deb"
        self.make_deb()
        self.manifest = self.root / "manifest.json"

    def tearDown(self):
        self.temp.cleanup()

    def make_deb(self, contents="package data\n"):
        build = self.root / "build"
        (build / "DEBIAN").mkdir(parents=True, exist_ok=True)
        (build / "DEBIAN" / "control").write_text(
            "Package: beyla\nVersion: 1.2.3\nArchitecture: amd64\nDescription: test fixture\n"
        )
        (build / "payload").write_text(contents)
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(build), str(self.package)], check=True, capture_output=True)

    def run_cli(self, *args, env=None, success=True):
        result = subprocess.run(["python3", str(SCRIPT), *map(str, args)], text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def test_create_verify_and_run_identity(self):
        env = dict(os.environ, GITHUB_RUN_ID="1234", GITHUB_RUN_ATTEMPT="2")
        self.run_cli("create", self.package, self.manifest, "--source", self.source, env=env)
        data = json.loads(self.manifest.read_text())
        self.assertEqual(data["package"], "beyla")
        self.assertEqual(data["source"], {"commit": subprocess.check_output(["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True).strip(), "dirty": False, "mode": "ci"})
        self.assertEqual((data["github_run_id"], data["github_run_attempt"]), ("1234", "2"))
        self.run_cli("verify", self.package, self.manifest, "--source", self.source, "--run-id", "1234", "--run-attempt", "2")
        self.run_cli("verify", self.package, self.manifest, "--source", self.source, "--run-id", "999", success=False)

    def test_ci_rejects_dirty_and_local_records_dirty(self):
        (self.source / "tracked").write_text("changed\n")
        self.run_cli("create", self.package, self.manifest, "--source", self.source, success=False)
        self.run_cli("create", self.package, self.manifest, "--source", self.source, "--mode", "local")
        data = json.loads(self.manifest.read_text())
        self.assertEqual(data["source"]["mode"], "local")
        self.assertTrue(data["source"]["dirty"])
        self.run_cli("verify", self.package, self.manifest, "--source", self.source)

    def test_tampered_deb_fails_verification(self):
        self.run_cli("create", self.package, self.manifest, "--source", self.source)
        self.make_deb("tampered\n")
        self.run_cli("verify", self.package, self.manifest, "--source", self.source, success=False)


if __name__ == "__main__":
    unittest.main()
