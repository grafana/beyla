"""Hypercorn launch parsing."""

from ..model import Launch, TARGET_MODULE, TARGET_NONE
from .arguments import argparse_positionals
from .common import classify_target, clean_value, valid_module


HYPERCORN_WITH_VALUES = set("""
--access-log --access-logfile --access-logformat --backlog -b --bind --ca-certs
--certfile --cert-reqs --ciphers -c --config --error-log --error-logfile --log-file
--graceful-timeout --read-timeout --max-requests --max-requests-jitter -g --group -k
--worker-class --keep-alive --keyfile --keyfile-password --insecure-bind --log-config
--log-level -p --pid --quic-bind --root-path --server-name --statsd-host
--statsd-prefix -m --umask -u --user --verify-mode --websocket-ping-interval -w --workers
""".split())
HYPERCORN_WITHOUT_VALUES = {"-D", "--daemon", "--debug", "--reload", "-h", "--help"}


def parse_hypercorn(args, env):
    """Parse a Hypercorn launch."""
    positionals = argparse_positionals(args, HYPERCORN_WITH_VALUES, HYPERCORN_WITHOUT_VALUES)
    if positionals is None or len(positionals) != 1:
        return Launch()
    target, kind = _hypercorn_application(positionals[0])
    if not target:
        return Launch()
    return Launch(target=target, target_kind=kind, search_paths=["."])


def _hypercorn_application(application):
    """Validate and normalize a Hypercorn application target."""
    if clean_value(application) != application:
        return "", TARGET_NONE
    parts = application.split(":")
    if len(parts) == 1:
        module, obj = parts[0], ""
    elif len(parts) == 2:
        module, obj = parts
    elif len(parts) == 3 and parts[0] in {"asgi", "wsgi"}:
        module, obj = parts[1:]
    else:
        return "", TARGET_NONE
    if not module or len(parts) > 1 and not obj:
        return "", TARGET_NONE
    kind = classify_target(module)
    if kind == TARGET_MODULE and not valid_module(module):
        return "", TARGET_NONE
    return module + ((":" + obj) if obj else ""), kind

