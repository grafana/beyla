"""Celery launch parsing."""

from ..model import Launch
from .common import classify_target


def parse_celery(args, env):
    """Parse a Celery launch."""
    target = env.get("CELERY_APP", "")
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-A", "--app"} and index + 1 < len(args):
            index += 1
            target = args[index]
        elif arg.startswith("--app="):
            target = arg.split("=", 1)[1]
        elif arg.startswith("-A") and len(arg) > 2:
            target = arg[2:].lstrip("=")
        index += 1
    return Launch(target=target, target_kind=classify_target(target))

