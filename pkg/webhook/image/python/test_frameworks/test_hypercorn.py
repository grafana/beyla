"""Tests for Hypercorn launch parsing."""

import unittest

from _beyla_otel.frameworks.hypercorn import (
    HYPERCORN_WITH_VALUES,
    HYPERCORN_WITHOUT_VALUES,
    parse_hypercorn,
)
from _beyla_otel.model import Launch


EXPECTED_WITH_VALUES = set("""
--access-log --access-logfile --access-logformat --backlog -b --bind --ca-certs
--certfile --cert-reqs --ciphers -c --config --error-log --error-logfile --log-file
--graceful-timeout --read-timeout --max-requests --max-requests-jitter -g --group -k
--worker-class --keep-alive --keyfile --keyfile-password --insecure-bind --log-config
--log-level -p --pid --quic-bind --root-path --server-name --statsd-host
--statsd-prefix -m --umask -u --user --verify-mode --websocket-ping-interval -w --workers
""".split())
EXPECTED_WITHOUT_VALUES = {"-D", "--daemon", "--debug", "--reload", "-h", "--help"}


class TestHypercornParsing(unittest.TestCase):
    def test_every_option_with_a_value(self):
        self.assertEqual(EXPECTED_WITH_VALUES, HYPERCORN_WITH_VALUES)
        for option in EXPECTED_WITH_VALUES:
            with self.subTest(option=option):
                launch = parse_hypercorn([option, "env:prod", "orders.asgi:app"], {})
                self.assertEqual("orders.asgi:app", launch.target)

    def test_every_flag(self):
        self.assertEqual(EXPECTED_WITHOUT_VALUES, HYPERCORN_WITHOUT_VALUES)
        for option in EXPECTED_WITHOUT_VALUES:
            with self.subTest(option=option):
                launch = parse_hypercorn([option, "orders.asgi:app"], {})
                self.assertEqual("orders.asgi:app", launch.target)

    def test_application_forms(self):
        cases = [
            ("orders.asgi", "orders.asgi", "module"),
            ("orders.asgi:app", "orders.asgi:app", "module"),
            ("asgi:orders.asgi", "asgi:orders.asgi", "module"),
            ("asgi:orders.asgi:app", "orders.asgi:app", "module"),
            ("wsgi:orders.wsgi:application", "orders.wsgi:application", "module"),
            ("src/orders.py:app", "src/orders.py:app", "file"),
            ("wsgi:src/orders.py:app", "src/orders.py:app", "file"),
        ]
        for argument, target, kind in cases:
            with self.subTest(argument=argument):
                launch = parse_hypercorn([argument], {})
                self.assertEqual((target, kind), (launch.target, launch.target_kind))
                self.assertEqual(["."], launch.search_paths)

    def test_recognized_option_forms(self):
        cases = [
            ["--bind", ":8000", "orders.asgi:app"],
            ["--bind=:8000", "orders.asgi:app"],
            ["-b", ":8000", "orders.asgi:app"],
            ["-b:8000", "orders.asgi:app"],
            ["-w=4", "orders.asgi:app"],
            ["-Db:8000", "orders.asgi:app"],
            ["--workers", "-1", "orders.asgi:app"],
            ["-w", "-1", "orders.asgi:app"],
            ["--access-logfile", "-", "orders.asgi:app"],
            ["--access-logfile=-", "orders.asgi:app"],
            ["--config", "python:settings", "orders.asgi:app"],
            ["--config=python:settings", "orders.asgi:app"],
            ["--reload", "orders.asgi:app"],
            ["orders.asgi:app", "--access-logfile", "-"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual("orders.asgi:app", parse_hypercorn(args, {}).target)

    def test_option_terminator_stops_option_parsing(self):
        launch = parse_hypercorn(["--", "orders.asgi:app"], {})

        self.assertEqual("orders.asgi:app", launch.target)

    def test_invalid_arguments_fail_closed(self):
        cases = [
            [],
            ["orders.asgi:app", "inventory.asgi:app"],
            ["--future-option", "value", "orders.asgi:app"],
            ["--future-option=value", "orders.asgi:app"],
            ["-Z", "orders.asgi:app"],
            ["-DZ", "orders.asgi:app"],
            ["orders.asgi:app", "--future-option", "value"],
            ["--bind"],
            ["--access-logfile", "--future-option", "value", "orders.asgi:app"],
            ["--reload=true", "orders.asgi:app"],
            ["--cipher", "value", "orders.asgi:app"],
            ["--paste", "config:prod", "orders.asgi:app"],
            ["--version", "orders.asgi:app"],
            ["orders-api:app"],
            ["orders.asgi:"],
            ["unknown:orders.asgi:app"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(Launch(), parse_hypercorn(args, {}))


if __name__ == "__main__":
    unittest.main()
