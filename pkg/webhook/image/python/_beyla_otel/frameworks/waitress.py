"""Waitress launch parsing."""

from ..model import Launch, TARGET_DOTTED_REFERENCE, TARGET_MODULE
from .arguments import separated_option_value
from .common import application_reference, clean_value, valid_module


WAITRESS_WITH_VALUES = set("""
--host --port --listen --threads --trusted-proxy --trusted-proxy-count
--trusted-proxy-headers --url-scheme --url-prefix --backlog --recv-bytes --send-bytes
--outbuf-overflow --outbuf-high-watermark --inbuf-overflow --connection-limit
--cleanup-interval --channel-timeout --max-request-header-size --max-request-body-size
--ident --asyncore-loop-timeout --unix-socket --unix-socket-perms --sockets
--channel-request-lookahead --server-name --app
""".split())
WAITRESS_WITHOUT_VALUES = set("""
--help --call --ipv4 --no-ipv4 --ipv6 --no-ipv6 --log-untrusted-proxy-headers
--no-log-untrusted-proxy-headers --clear-untrusted-proxy-headers --no-clear-untrusted-proxy-headers
--log-socket-errors --no-log-socket-errors --expose-tracebacks --no-expose-tracebacks
--asyncore-use-poll --no-asyncore-use-poll
""".split())


def parse_waitress(args, env):
    """Parse a Waitress launch."""
    target = _waitress_application(args)
    if target is None or clean_value(target) != target:
        return Launch()
    if application_reference(target, strict=True):
        return Launch(target=target, target_kind=TARGET_MODULE)
    if "." in target and valid_module(target):
        return Launch(target=target, target_kind=TARGET_DOTTED_REFERENCE)
    return Launch()


def _waitress_application(args):
    """Extract a single Waitress application target."""
    app = ""
    positionals = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            positionals.extend(args[index + 1:])
            break
        if not arg.startswith("-") or arg == "-":
            positionals.extend(args[index:])
            break
        if not arg.startswith("--"):
            return None
        name, separator, value = arg.partition("=")
        if name in WAITRESS_WITH_VALUES:
            if not separator:
                index += 1
                if index == len(args) or not separated_option_value(args[index]):
                    return None
                value = args[index]
            if name == "--app":
                app = value
        elif name not in WAITRESS_WITHOUT_VALUES or separator:
            return None
        index += 1
    if app:
        return app if not positionals else None
    return positionals[0] if len(positionals) == 1 else None

