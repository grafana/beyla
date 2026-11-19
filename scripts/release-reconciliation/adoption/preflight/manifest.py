"""Build a bounded, path-validated initial-adoption Git API manifest."""

import os
import re
import subprocess
from pathlib import Path

ALLOWED = (
    ".obi-src",
    "go.mod",
    "go.sum",
    "internal/testgenerated/",
    "schemas/",
    "vendor/",
    "scripts/generate-obi-tests.sh",
    "scripts/tests/mise-task-contracts.sh",
    "scripts/extend-beyla-kafka-oats-window.sh",
)
SHA = re.compile(r"^[0-9a-f]{40}$")


def run(args, repo):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, timeout=30
    ).stdout


def allowed(path):
    return (
        path == ".obi-src"
        or path in ALLOWED
        or any(path.startswith(p) for p in ALLOWED if p.endswith("/"))
    )


def build(base, target, repo="."):
    if not SHA.fullmatch(base or "") or not SHA.fullmatch(target or ""):
        raise ValueError("Manifest requires full lowercase base and OBI SHAs.")
    diff = run(["diff", "--cached", "--name-status", "-z", base, "--"], repo)
    fields = diff.decode("utf-8", "strict").split("\0")
    fields = [x for x in fields if x]
    changes, seen, total = [], set(), 0
    index = 0
    while index < len(fields):
        status, path = fields[index], fields[index + 1]
        index += 2
        if status not in {"A", "M", "D"} or not allowed(path) or path in seen:
            raise ValueError(
                "Candidate contains a rename, unexpected path, or duplicate change."
            )
        seen.add(path)
        if path == ".obi-src":
            if status not in {"A", "M"}:
                raise ValueError("The OBI gitlink cannot be deleted.")
            changes.append(
                {"path": path, "mode": "160000", "type": "commit", "sha": target}
            )
            continue
        old = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", f"{base}:{path}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        base_blob = old.stdout.strip() if old.returncode == 0 else None
        if status == "D":
            if not base_blob:
                raise ValueError("Deleted candidate path is absent from base.")
            tree = (
                run(["ls-tree", base, "--", path], repo)
                .decode("utf-8", "strict")
                .strip()
                .split()
            )
            mode = tree[0] if tree else ""
            if mode not in {"100644", "100755"}:
                raise ValueError("Deleted candidate path has an unsupported base mode.")
            changes.append(
                {
                    "path": path,
                    "mode": mode,
                    "type": "blob",
                    "delete": True,
                    "sha": None,
                }
            )
            continue
        staged = run(["ls-files", "--stage", "--", path], repo).decode().strip().split()
        if len(staged) < 3 or staged[0] not in {"100644", "100755"}:
            raise ValueError("Candidate contains a non-regular file.")
        with open(Path(repo) / path, "rb") as stream:
            raw = stream.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Candidate file exceeds the 2 MB publication limit.")
        content = raw.decode("utf-8", "strict")
        total += len(raw)
        if total > 20_000_000:
            raise ValueError("Candidate exceeds the 20 MB publication limit.")
        changes.append(
            {"path": path, "mode": staged[0], "type": "blob", "content": content}
        )
    if ".obi-src" not in seen or not changes or len(changes) > 500:
        raise ValueError(
            "Candidate must include its exact OBI gitlink and no more than 500 entries."
        )
    return changes


if __name__ == "__main__":
    changes = build(os.environ["BASE_SHA"], os.environ["OBI_SHA"])
    print(f"Validated {len(changes)} candidate changes.")
