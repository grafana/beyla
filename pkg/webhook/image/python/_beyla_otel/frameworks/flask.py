"""Flask launch parsing."""

from ..model import Launch, TARGET_MODULE
from .common import classify_target


def parse_flask(args, env):
    """Parse a Flask launch."""
    target = env.get("FLASK_APP", "")
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg in {"-A", "--app"} and index + 1 < len(args):
            index += 1
            target = args[index]
        elif arg.startswith("-A") and len(arg) > 2:
            target = arg[2:].lstrip("=")
        elif arg.startswith("--app="):
            target = arg.split("=", 1)[1]
        index += 1
    if not target:
        return Launch(flask_auto=True)
    kind = classify_target(target)
    return Launch(target=target, target_kind=kind, search_paths=["."] if kind == TARGET_MODULE else [])

