#!/usr/bin/env python3
"""Create and verify a local provenance manifest for an unpublished DEB.

CI creation requires a clean git checkout. For deliberate local experiments,
pass ``--mode local``; the manifest records whether that checkout was dirty.
This tool does not publish artifacts or contact external services.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PACKAGE_NAME = "beyla"
SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")


class ManifestError(Exception):
    pass


def git(root, *args):
    try:
        return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ManifestError(f"git command failed: {exc}") from exc


def source_state(root):
    commit = git(root, "rev-parse", "HEAD")
    if not SHA_RE.fullmatch(commit):
        raise ManifestError("git returned an invalid source commit")
    dirty = bool(git(root, "status", "--porcelain", "--untracked-files=normal"))
    return commit, dirty


def deb_field(package, field):
    try:
        value = subprocess.check_output(
            ["dpkg-deb", "-f", str(package), field], text=True, stderr=subprocess.PIPE
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ManifestError(f"cannot read DEB {field}: {exc}") from exc
    if not value:
        raise ManifestError(f"DEB has empty {field} metadata")
    return value


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def optional_identity(env_name, value):
    value = value if value is not None else os.environ.get(env_name)
    if value is not None and not re.fullmatch(r"[0-9]+", value):
        raise ManifestError(f"{env_name} must be numeric")
    return value


def create(args):
    root = args.source.resolve()
    package = args.package.resolve()
    output = args.manifest.resolve()
    if not package.is_file():
        raise ManifestError(f"DEB does not exist: {package}")
    name, version, arch = (deb_field(package, field) for field in ("Package", "Version", "Architecture"))
    if name != PACKAGE_NAME:
        raise ManifestError(f"expected package {PACKAGE_NAME}, found {name}")
    expected_filename = f"{name}_{version}_{arch}.deb"
    if package.name != expected_filename:
        raise ManifestError(f"DEB filename must be {expected_filename}")
    commit, dirty = source_state(root)
    if args.mode == "ci" and dirty:
        raise ManifestError("CI mode refuses a dirty git source tree; use --mode local for an explicit local build")
    run_id = optional_identity("GITHUB_RUN_ID", args.run_id)
    run_attempt = optional_identity("GITHUB_RUN_ATTEMPT", args.run_attempt)
    data = {
        "architecture": arch,
        "deb_filename": package.name,
        "package": name,
        "sha256": sha256(package),
        "source": {"commit": commit, "dirty": dirty, "mode": args.mode},
        "version": version,
    }
    if run_id is not None:
        data["github_run_id"] = run_id
    if run_attempt is not None:
        data["github_run_attempt"] = run_attempt
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote artifact manifest: {output}")


def verify(args):
    root = args.source.resolve()
    package = args.package.resolve()
    try:
        data = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    required = {"package", "version", "architecture", "deb_filename", "sha256", "source"}
    if not isinstance(data, dict) or not required.issubset(data):
        raise ManifestError("manifest is missing required fields")
    if data["package"] != PACKAGE_NAME or data["deb_filename"] != package.name:
        raise ManifestError("manifest package or DEB filename does not match")
    if not package.is_file():
        raise ManifestError(f"DEB does not exist: {package}")
    actual = {field.lower(): deb_field(package, field) for field in ("Package", "Version", "Architecture")}
    for key in ("package", "version", "architecture"):
        if data[key] != actual[key]:
            raise ManifestError(f"DEB {key} metadata does not match manifest")
    expected_name = f"{actual['package']}_{actual['version']}_{actual['architecture']}.deb"
    if package.name != expected_name:
        raise ManifestError(f"DEB filename must be {expected_name}")
    if data["sha256"] != sha256(package):
        raise ManifestError("DEB SHA256 does not match manifest")
    source = data["source"]
    if not isinstance(source, dict) or not SHA_RE.fullmatch(str(source.get("commit", ""))):
        raise ManifestError("manifest has an invalid source commit")
    if source.get("mode") not in ("ci", "local") or not isinstance(source.get("dirty"), bool):
        raise ManifestError("manifest has invalid source mode/state")
    if source["mode"] == "ci" and source["dirty"]:
        raise ManifestError("CI manifest cannot describe a dirty source tree")
    commit, dirty = source_state(root)
    if source["mode"] == "ci" and dirty:
        raise ManifestError("CI verification refuses a dirty git source tree")
    if commit != source["commit"] or dirty != source["dirty"]:
        raise ManifestError("current git source commit/dirty state does not match manifest")
    for key, arg_name, env in (("github_run_id", "run_id", "GITHUB_RUN_ID"), ("github_run_attempt", "run_attempt", "GITHUB_RUN_ATTEMPT")):
        expected = optional_identity(env, getattr(args, arg_name))
        if expected is not None and data.get(key) != expected:
            raise ManifestError(f"{key} does not match expected run identity")
    print("Artifact manifest verified")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create_parser = sub.add_parser("create", help="write a JSON manifest for a DEB")
    create_parser.add_argument("package", type=Path)
    create_parser.add_argument("manifest", type=Path)
    create_parser.add_argument("--source", type=Path, default=Path.cwd())
    create_parser.add_argument("--mode", choices=("ci", "local"), default="ci", help="CI requires clean source; local permits and records dirty source")
    create_parser.add_argument("--run-id")
    create_parser.add_argument("--run-attempt")
    create_parser.set_defaults(func=create)
    verify_parser = sub.add_parser("verify", help="verify a DEB against its JSON manifest")
    verify_parser.add_argument("package", type=Path)
    verify_parser.add_argument("manifest", type=Path)
    verify_parser.add_argument("--source", type=Path, default=Path.cwd())
    verify_parser.add_argument("--run-id")
    verify_parser.add_argument("--run-attempt")
    verify_parser.set_defaults(func=verify)
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ManifestError as exc:
        print(f"artifact_manifest: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
