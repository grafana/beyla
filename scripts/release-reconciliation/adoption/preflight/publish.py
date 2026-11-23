"""Create-only trusted publisher for a preflighted exact-SHA OBI adoption."""

import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ADOPTION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ADOPTION_DIR))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from manifest import build
from obi_adoption_repair import GitHub, RepairError, create_git_commit, create_ref

SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = "grafana/beyla"


def api(token, method, path, body=None, repo=REPO):
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(
        "https://api.github.com/repos/" + repo + path,
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "grafana-beyla-obi-adoption",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.loads(response.read()) if response.status != 204 else None
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and method == "GET":
            return None
        raise RuntimeError(f"GitHub API {method} failed with HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"GitHub API {method} failed or timed out.") from exc


def validate_no_open_pin_pr(token):
    prs = api(token, "GET", "/pulls?state=open&base=main&per_page=100&page=1")
    if not isinstance(prs, list) or len(prs) >= 100:
        raise RuntimeError(
            "Open PR inventory is incomplete; refuse candidate publication."
        )
    for pr in prs:
        if pr.get("changed_files", 0) > 100:
            raise RuntimeError("Open PR file inventory is incomplete.")
        files = api(token, "GET", f"/pulls/{pr['number']}/files?per_page=100&page=1")
        if not isinstance(files, list) or len(files) >= 100:
            raise RuntimeError("Open PR file inventory is incomplete.")
        if any(entry.get("filename") == ".obi-src" for entry in files):
            raise RuntimeError(
                "An active PR that changes the OBI pin appeared; preserve it and defer this candidate."
            )


def validate_source(token):
    number, sha = os.getenv("SOURCE_PR", ""), os.getenv("SOURCE_SHA", "")
    if not number and not sha:
        return
    if not number.isdigit() or not SHA.fullmatch(sha):
        raise RuntimeError(
            "Optional source PR and exact source SHA must be supplied together."
        )
    pr = api(token, "GET", f"/pulls/{number}")
    if (
        not pr
        or pr.get("state") != "open"
        or pr.get("base", {}).get("ref") != "main"
        or pr.get("base", {}).get("repo", {}).get("full_name") != REPO
        or pr.get("head", {}).get("repo", {}).get("full_name") != REPO
        or pr.get("head", {}).get("sha") != sha
    ):
        raise RuntimeError(
            "Optional source PR changed or no longer matches its exact selected head."
        )


def validate_source_reachability(token, target):
    repo = "open-telemetry/opentelemetry-ebpf-instrumentation"
    head = api(token, "GET", "/commits/main", repo=repo)
    if not head or not SHA.fullmatch(head.get("sha", "")):
        raise RuntimeError(
            "Could not sample current OBI main for exact-SHA reachability recheck."
        )
    comparison = api(token, "GET", f"/compare/{target}...{head['sha']}", repo=repo)
    if not comparison or comparison.get("status") not in {"ahead", "identical"}:
        raise RuntimeError(
            "Selected OBI SHA is no longer proven reachable from upstream OBI main."
        )


def apply_candidate_patch(repo, patch):
    """Apply the artifact exactly once to the trusted, clean base checkout."""
    subprocess.run(
        ["git", "-C", str(repo), "apply", "--check", "--index", "--binary", str(patch)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "-C", str(repo), "apply", "--index", "--binary", str(patch)],
        check=True,
        capture_output=True,
        timeout=30,
    )


def main():
    base, target = os.environ["BASE_SHA"], os.environ["OBI_SHA"]
    branch = f"update-obi-adoption-{target}"
    if not SHA.fullmatch(base) or not SHA.fullmatch(target):
        raise RuntimeError("Publisher needs full base and selected OBI SHAs.")
    if os.getenv("BRANCH") != branch:
        raise RuntimeError(
            "Prepared branch name does not match the immutable selected OBI SHA."
        )
    app_token = os.environ["APP_TOKEN"]
    read_token = os.environ["GH_TOKEN"]
    github = GitHub(REPO, read_token, write_token=app_token)
    main = api(read_token, "GET", "/commits/main")
    if not main or main.get("sha") != base:
        raise RuntimeError(
            "Beyla main changed after preflight; rerun from the new base."
        )
    validate_no_open_pin_pr(read_token)
    validate_source(read_token)
    validate_source_reachability(read_token, target)
    if api(read_token, "GET", "/git/ref/heads/" + branch):
        raise RuntimeError(
            "Managed branch already exists; never adopt or overwrite an unverified branch."
        )
    patch = Path(os.environ["PATCH"])
    payload = patch.read_bytes()
    if hashlib.sha256(payload).hexdigest() != os.environ.get("PATCH_SHA256"):
        raise RuntimeError(
            "Adoption artifact digest does not match the prepared exact-SHA candidate."
        )
    metadata = (patch.parent / "metadata.txt").read_text(encoding="utf-8").splitlines()
    expected_metadata = {
        f"base_sha={base}",
        f"obi_sha={target}",
        f"source_pr={os.getenv('SOURCE_PR', '')}",
        f"source_sha={os.getenv('SOURCE_SHA', '')}",
        f"patch_sha256={os.environ['PATCH_SHA256']}",
    }
    if not expected_metadata.issubset(set(metadata)):
        raise RuntimeError(
            "Adoption artifact metadata does not match the selected source and base."
        )
    apply_candidate_patch(ROOT, patch)
    subprocess.run(
        ["git", "-C", ".obi-src", "fetch", "--depth=1", "--no-tags", "origin", target],
        check=True,
        capture_output=True,
        timeout=180,
    )
    subprocess.run(
        ["git", "-C", ".obi-src", "checkout", "--detach", target],
        check=True,
        capture_output=True,
        timeout=30,
    )
    subprocess.run(["git", "add", "--", ".obi-src"], check=True, timeout=30)
    changes = build(base, target)
    executable_paths = frozenset(
        change["path"] for change in changes if change.get("mode") == "100755"
    )
    commit_sha = create_git_commit(
        github,
        parent_sha=base,
        changes=changes,
        allow_executable_paths=executable_paths,
        message=f"Adopt OBI {target} with generator cleanup",
    )
    # The helper checks GitHub's verified-signature response before this create-only ref write.
    latest_main = api(read_token, "GET", "/commits/main")
    if not latest_main or latest_main.get("sha") != base:
        raise RuntimeError(
            "Beyla main changed while the signed candidate commit was being prepared."
        )
    validate_source(read_token)
    validate_source_reachability(read_token, target)
    validate_no_open_pin_pr(read_token)
    if api(read_token, "GET", "/git/ref/heads/" + branch):
        raise RuntimeError(
            "Managed branch appeared during publication; refuse to overwrite it."
        )
    create_ref(github, branch=branch, sha=commit_sha)
    source_pr, source_sha = os.getenv("SOURCE_PR", ""), os.getenv("SOURCE_SHA", "")
    detail = (
        f"Optional compatibility cleanup source: PR #{source_pr} at `{source_sha}`."
        if source_pr
        else "No separate cleanup PR was selected."
    )
    marker = f"<!-- grafana-beyla-obi-adoption:v1 target={target} base={base} -->"
    body = (
        f"{marker}\nI prepared this candidate from OBI commit `{target}` and Beyla main `{base}`.\n"
        f"{detail}\n\nThis draft atomically pins the exact OBI commit and includes generated/vendor/compatibility changes. "
        "Human review and merge are required; no auto-merge is enabled."
    )
    pr = api(
        app_token,
        "POST",
        "/pulls",
        {
            "title": f"Adopt OBI {target} with generator cleanup",
            "head": branch,
            "base": "main",
            "body": body,
            "draft": True,
        },
    )
    if (
        not isinstance(pr, dict)
        or not isinstance(pr.get("number"), int)
        or pr.get("draft") is not True
    ):
        raise RuntimeError("Draft PR creation did not return the expected identity.")
    api(app_token, "POST", f"/issues/{pr['number']}/labels", ["automated-pr"])
    print(
        json.dumps(
            {
                "number": pr["number"],
                "head_sha": pr.get("head", {}).get("sha"),
                "branch": branch,
                "created": True,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, RuntimeError, RepairError) as exc:
        print(f"OBI adoption publication blocked: {exc}", file=sys.stderr)
        raise SystemExit(1)
