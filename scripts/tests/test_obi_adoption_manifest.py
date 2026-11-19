import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

path = Path(__file__).parents[1] / "obi-adoption-preflight" / "manifest.py"
spec = importlib.util.spec_from_file_location("obi_manifest", path)
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)
publisher_path = Path(__file__).parents[1] / "obi-adoption-preflight" / "publish.py"
publisher_spec = importlib.util.spec_from_file_location("obi_publisher", publisher_path)
publisher = importlib.util.module_from_spec(publisher_spec)
publisher_spec.loader.exec_module(publisher)


class ManifestTests(unittest.TestCase):
    def git(self, repo, *args):
        return subprocess.run(
            ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def test_build_binds_gitlink_and_validated_text_diffs(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "test")
            self.git(repo, "config", "user.email", "test@example.invalid")
            (repo / "go.mod").write_text("module example\n")
            (repo / "scripts").mkdir()
            helper = repo / "scripts/generate-obi-tests.sh"
            helper.write_text("#!/bin/sh\necho generated\n")
            helper.chmod(0o755)
            obsolete = repo / "scripts/extend-beyla-kafka-oats-window.sh"
            obsolete.write_text("#!/bin/sh\nexit 0\n")
            obsolete.chmod(0o755)
            self.git(repo, "add", "go.mod", "scripts")
            self.git(repo, "commit", "-qm", "base")
            target, next_target = "a" * 40, "b" * 40
            self.git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{target},.obi-src",
            )
            self.git(repo, "commit", "-qm", "pin")
            base = self.git(repo, "rev-parse", "HEAD")
            (repo / "go.mod").write_text("module example\n// generated\n")
            helper.write_text("#!/bin/sh\necho updated\n")
            obsolete.unlink()
            (repo / "vendor").mkdir()
            (repo / "vendor/module.txt").write_text("# module\n")
            self.git(
                repo,
                "add",
                "go.mod",
                "scripts/generate-obi-tests.sh",
                "scripts/extend-beyla-kafka-oats-window.sh",
                "vendor/module.txt",
            )
            self.git(
                repo, "update-index", "--cacheinfo", f"160000,{next_target},.obi-src"
            )
            changes = manifest.build(base, next_target, repo)
            self.assertEqual(
                {
                    ".obi-src",
                    "go.mod",
                    "scripts/generate-obi-tests.sh",
                    "scripts/extend-beyla-kafka-oats-window.sh",
                    "vendor/module.txt",
                },
                {item["path"] for item in changes},
            )
            link = next(item for item in changes if item["path"] == ".obi-src")
            self.assertEqual(next_target, link["sha"])
            executable = next(
                item
                for item in changes
                if item["path"] == "scripts/generate-obi-tests.sh"
            )
            deleted = next(
                item
                for item in changes
                if item["path"] == "scripts/extend-beyla-kafka-oats-window.sh"
            )
            self.assertEqual("100755", executable["mode"])
            self.assertEqual("100755", deleted["mode"])
            self.assertTrue(deleted["delete"])

    def test_rejects_out_of_scope_candidate_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "test")
            self.git(repo, "config", "user.email", "test@example.invalid")
            (repo / "go.mod").write_text("module example\n")
            self.git(repo, "add", "go.mod")
            self.git(repo, "commit", "-qm", "base")
            target = "a" * 40
            self.git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{target},.obi-src",
            )
            self.git(repo, "commit", "-qm", "pin")
            base = self.git(repo, "rev-parse", "HEAD")
            (repo / "README.md").write_text("unexpected\n")
            self.git(repo, "add", "README.md")
            self.git(repo, "update-index", "--cacheinfo", f"160000,{'b' * 40},.obi-src")
            with self.assertRaises(ValueError):
                manifest.build(base, "b" * 40, repo)

    def test_new_different_target_open_pr_blocks_publication_race(self):
        from unittest.mock import patch

        active = {"number": 42, "changed_files": 1, "head": {"sha": "c" * 40}}
        with (
            patch.object(
                publisher, "api", side_effect=[[active], [{"filename": ".obi-src"}]]
            ),
            self.assertRaisesRegex(RuntimeError, "changes the OBI pin"),
        ):
            publisher.validate_no_open_pin_pr("read-only-token")

    def test_candidate_patch_is_applied_once_to_base_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "test")
            self.git(repo, "config", "user.email", "test@example.invalid")
            file = repo / "go.mod"
            file.write_text("module before\n")
            self.git(repo, "add", "go.mod")
            self.git(repo, "commit", "-qm", "base")
            file.write_text("module after\n")
            patch_file = repo / "candidate.patch"
            patch_file.write_bytes(
                subprocess.run(
                    ["git", "-C", str(repo), "diff", "--binary"],
                    check=True,
                    capture_output=True,
                ).stdout
            )
            file.write_text("module before\n")
            publisher.apply_candidate_patch(repo, patch_file)
            self.assertEqual("module after\n", file.read_text())
            with self.assertRaises(subprocess.CalledProcessError):
                publisher.apply_candidate_patch(repo, patch_file)


if __name__ == "__main__":
    unittest.main()
