"""Daphne launch parsing."""

from .arguments import argparse_application


DAPHNE_WITH_VALUES = set("""
-p --port -b --bind --websocket_timeout --websocket_connect_timeout -u
--unix-socket --fd -e --endpoint -v --verbosity -t --http-timeout
--access-log --log-fmt --ping-interval --ping-timeout --websocket-max-message-size
--websocket-max-frame-size --application-close-timeout --root-path --proxy-headers-host
--proxy-headers-port -s --server-name
""".split())
DAPHNE_WITHOUT_VALUES = {"--proxy-headers", "--no-server-name", "-h", "--help"}


def parse_daphne(args, env):
    """Parse a Daphne launch."""
    return argparse_application(args, DAPHNE_WITH_VALUES, DAPHNE_WITHOUT_VALUES)

