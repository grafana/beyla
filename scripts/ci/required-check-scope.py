#!/usr/bin/env python3
"""Classify whether a changed-file snapshot applies to a required check."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import PurePosixPath

FORCED_PATHS = {
    ".github/workflows/_required-check-scope.yml",
    "scripts/ci/required-check-scope.py",
    "scripts/ci/test_required_check_scope.py",
}


def parse_patterns(text: str) -> list[str]:
    patterns = [line.strip() for line in text.splitlines() if line.strip()]
    if not patterns:
        raise ValueError("no path patterns configured")
    for pattern in patterns:
        if pattern in FORCED_PATHS:
            continue
        if pattern == "**.go":
            continue
        if pattern.endswith("/**") and pattern.count("*") == 2 and "**" not in pattern[:-3]:
            prefix = pattern[:-3]
            if not prefix or prefix.startswith("/") or any(char in prefix for char in "?![]+") or ".." in PurePosixPath(prefix).parts:
                raise ValueError(f"unsupported path pattern: {pattern!r}")
            continue
        if any(char in pattern for char in "*?![]+") or pattern.startswith("/") or ".." in PurePosixPath(pattern).parts:
            raise ValueError(f"unsupported path pattern: {pattern!r}")
    return patterns


def matches(path: str, patterns: list[str]) -> bool:
    if path in FORCED_PATHS:
        return True
    for pattern in patterns:
        if pattern == "**.go" and path.endswith(".go"):
            return True
        if pattern.endswith("/**") and path.startswith(pattern[:-3] + "/"):
            return True
        if path == pattern:
            return True
    return False


def changed_paths(revision: str, cwd: str | None = None) -> list[str]:
    if not revision:
        raise ValueError("GITHUB_SHA is missing")
    result = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", f"{revision}^1", revision, "--"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
    )
    return [os.fsdecode(item) for item in result.stdout.split(b"\0") if item]


def classify(pattern_text: str, revision: str, cwd: str | None = None) -> bool:
    patterns = parse_patterns(pattern_text)
    return any(matches(path, patterns) for path in changed_paths(revision, cwd))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--patterns", required=True, help="newline-delimited path patterns")
    args = parser.parse_args()
    try:
        result = classify(args.patterns, os.environ.get("GITHUB_SHA", ""))
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"required-check-scope: {exc}", file=sys.stderr)
        return 1
    print(f"applicable={str(result).lower()}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"applicable={str(result).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
