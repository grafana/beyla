"""Django launch parsing."""

from ..model import Launch
from .arguments import last_long_option
from .common import classify_target


def parse_django(args, env):
    """Parse a Django launch."""
    target = last_long_option(args, "--settings", env.get("DJANGO_SETTINGS_MODULE", ""))
    python_path = last_long_option(args, "--pythonpath")
    return Launch(
        target=target,
        target_kind=classify_target(target),
        search_paths=[python_path] if python_path else [],
    )

