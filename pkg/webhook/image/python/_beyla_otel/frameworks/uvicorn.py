"""Uvicorn launch parsing."""

from ..model import Launch, TARGET_MODULE
from .common import clean_value, first_application_reference


UVICORN_WITH_VALUES = set("""
--host --port --uds --fd --reload-dir --reload-delay --reload-include --reload-exclude
--workers --env-file --timeout-worker-healthcheck --log-config --log-level --loop --http
--ws --ws-max-size --ws-max-queue --ws-ping-interval --ws-ping-timeout --ws-per-message-deflate
--lifespan --h11-max-incomplete-event-size --interface --root-path --forwarded-allow-ips --header
--ssl-keyfile --ssl-keyfile-password --ssl-certfile --ssl-version --ssl-cert-reqs --ssl-ca-certs
--ssl-ciphers --app-dir --limit-concurrency --backlog --limit-max-requests
--limit-max-requests-jitter --timeout-keep-alive --timeout-graceful-shutdown
""".split())
UVICORN_WITHOUT_VALUES = set("""
--reload --access-log --no-access-log --use-colors --no-use-colors --proxy-headers
--no-proxy-headers --server-header --no-server-header --date-header --no-date-header
--version --reset-contextvars --factory --help
""".split())


def parse_uvicorn(args, env):
    """Parse a Uvicorn launch."""
    positionals = _uvicorn_positionals(args)
    if positionals is None:
        return Launch()
    app_dir = env.get("UVICORN_APP_DIR", "")
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg == "--app-dir" and index + 1 < len(args):
            index += 1
            app_dir = args[index]
        elif arg.startswith("--app-dir="):
            app_dir = arg.split("=", 1)[1]
        index += 1
    app_dir = app_dir or "."
    launch = Launch(app_dir=app_dir, search_paths=[app_dir])
    target = first_application_reference(positionals) or clean_value(env.get("UVICORN_APP", ""))
    if target:
        launch.target = target
        launch.target_kind = TARGET_MODULE
    return launch


def _uvicorn_positionals(args):
    """Collect Uvicorn positionals while validating options."""
    values = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return values + args[index + 1:]
        if arg.startswith("--"):
            name, separator, _ = arg.partition("=")
            if name in UVICORN_WITH_VALUES:
                if not separator:
                    index += 1
                    if index == len(args):
                        return None
            elif name not in UVICORN_WITHOUT_VALUES or separator:
                return None
        elif arg.startswith("-") and arg != "-":
            return None
        else:
            values.append(arg)
        index += 1
    return values

