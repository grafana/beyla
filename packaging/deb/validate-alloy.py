#!/usr/bin/python3
"""Run Alloy validation with values from the root-only EnvironmentFile."""

import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Dict


def read_environment(path: Path) -> Dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, raw_value = line.split("=", 1)
        parsed = shlex.split(raw_value, comments=False, posix=True)
        values[key] = parsed[0] if parsed else ""
    return values


def package_root() -> Path:
    return Path(os.environ.get("BEYLA_PACKAGE_ROOT") or "/")


def main() -> int:
    root = package_root()
    config = root / "etc/beyla/config.alloy"
    environment = os.environ.copy()
    environment.update(read_environment(config.parent / "alloy.env"))
    return subprocess.run(
        ["alloy", "validate", "--stability.level=public-preview", str(config)],
        env=environment,
        check=False,
    ).returncode


if __name__ == "__main__":
    sys.exit(main())
