import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("required-check-scope.py")
SPEC = importlib.util.spec_from_file_location("required_check_scope", MODULE_PATH)
scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scope)


class PatternTests(unittest.TestCase):
    def test_supported_forms_and_matching(self):
        patterns = scope.parse_patterns("src/main.go\ninternal/**\n**.go\n")
        self.assertTrue(scope.matches("src/main.go", patterns))
        self.assertTrue(scope.matches("internal/deep/file.txt", patterns))
        self.assertTrue(scope.matches("nested/file.go", patterns))
        self.assertFalse(scope.matches("internality/file.txt", patterns))
        self.assertFalse(scope.matches("README.md", patterns))

    def test_invalid_or_missing_patterns_fail_closed(self):
        for text in ("", "src/*.go", "../secret", "/absolute/**"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                scope.parse_patterns(text)


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")
        (self.repo / "src").mkdir()
        (self.repo / "src/old.go").write_text("initial\n")
        self.git("add", "--", "src")
        self.git("commit", "-qm", "base")
        self.parent = self.git("rev-parse", "HEAD")

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def snapshot(self):
        self.git("add", "--", "src")
        self.git("commit", "--allow-empty", "-qm", "change")
        change = self.git("rev-parse", "HEAD")
        tree = self.git("rev-parse", f"{change}^{{tree}}")
        # GitHub's synthetic PR merge commit has the base as first parent.
        merge = self.git("commit-tree", tree, "-p", self.parent, "-p", change)
        self.git("update-ref", "refs/heads/test-merge", merge)
        return merge

    def test_deletion_and_rename_report_paths_from_snapshot(self):
        (self.repo / "src/old.go").unlink()
        (self.repo / "src/new.go").write_text("renamed\n")
        revision = self.snapshot()
        # --no-renames reports the deleted old name and added new name.
        paths = scope.changed_paths(revision, self.repo)
        self.assertEqual(set(paths), {"src/old.go", "src/new.go"})
        self.assertTrue(scope.classify("src/old.go", revision, self.repo))

    def test_spaces_and_non_utf8_paths_are_preserved(self):
        (self.repo / "src/with space.go").write_text("space\n")
        unusual = os.fsencode(self.repo) + b"/src/bad-\xff.go"
        fd = os.open(unusual, os.O_CREAT | os.O_WRONLY, 0o644)
        os.write(fd, b"bytes\n")
        os.close(fd)
        revision = self.snapshot()
        paths = scope.changed_paths(revision, self.repo)
        self.assertIn("src/with space.go", paths)
        self.assertTrue(any(os.fsencode(path) == b"src/bad-\xff.go" for path in paths))
        self.assertTrue(scope.classify("**.go", revision, self.repo))

    def test_empty_diff_is_not_applicable(self):
        revision = self.snapshot()
        self.assertFalse(scope.classify("src/old.go", revision, self.repo))

    def test_invalid_revision_fails_closed(self):
        with self.assertRaises(subprocess.CalledProcessError):
            scope.changed_paths("missing-revision", self.repo)

    def test_depth_two_file_clone_classifies_merge_snapshot(self):
        (self.repo / "src/shallow.go").write_text("changed in PR\n")
        revision = self.snapshot()
        checkout = self.repo.parent / (self.repo.name + "-checkout")
        try:
            subprocess.run(
                ["git", "clone", "--quiet", "--depth=2", "--branch", "test-merge",
                 self.repo.as_uri(), str(checkout)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(scope.changed_paths(revision, str(checkout)), ["src/shallow.go"])
            self.assertTrue(scope.classify("src/shallow.go", revision, str(checkout)))
        finally:
            import shutil
            shutil.rmtree(checkout, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
