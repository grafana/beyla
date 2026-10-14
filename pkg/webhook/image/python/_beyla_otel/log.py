"""Logging for the Beyla Python injector."""

import sys


PREFIX = "[Beyla OpenTelemetry Injector Python]"


def info(message):
    """Write an informational injector message."""
    print("{} {}".format(PREFIX, message))


def warning(message):
    """Write a non-fatal injector warning."""
    print("{} {}".format(PREFIX, message), file=sys.stderr)

