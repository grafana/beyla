"""Tests for Daphne launch parsing."""

import unittest

from _beyla_otel.frameworks.daphne import (
    DAPHNE_WITH_VALUES,
    DAPHNE_WITHOUT_VALUES,
    parse_daphne,
)
from _beyla_otel.model import Launch


EXPECTED_WITH_VALUES = set("""
-p --port -b --bind --websocket_timeout --websocket_connect_timeout -u
--unix-socket --fd -e --endpoint -v --verbosity -t --http-timeout
--access-log --log-fmt --ping-interval --ping-timeout --websocket-max-message-size
--websocket-max-frame-size --application-close-timeout --root-path --proxy-headers-host
--proxy-headers-port -s --server-name
""".split())
EXPECTED_WITHOUT_VALUES = {"--proxy-headers", "--no-server-name", "-h", "--help"}


class TestDaphneParsing(unittest.TestCase):
    def test_every_option_with_a_value(self):
        self.assertEqual(EXPECTED_WITH_VALUES, DAPHNE_WITH_VALUES)
        for option in EXPECTED_WITH_VALUES:
            with self.subTest(option=option):
                launch = parse_daphne([option, "env:prod", "orders.asgi:application"], {})
                self.assertEqual("orders.asgi:application", launch.target)

    def test_every_flag(self):
        self.assertEqual(EXPECTED_WITHOUT_VALUES, DAPHNE_WITHOUT_VALUES)
        for option in EXPECTED_WITHOUT_VALUES:
            with self.subTest(option=option):
                launch = parse_daphne([option, "orders.asgi:application"], {})
                self.assertEqual("orders.asgi:application", launch.target)

    def test_application_with_recognized_options(self):
        cases = [
            ["-b", "0.0.0.0", "-p", "8000", "orders.asgi:application"],
            ["--bind=0.0.0.0", "--port=8000", "orders.asgi:application"],
            ["-p=8000", "orders.asgi:application"],
            ["-vp8000", "orders.asgi:application"],
            ["--http-timeout", "-1", "orders.asgi:application"],
            ["--access-log", "-", "orders.asgi:application"],
            ["--access-log=-", "orders.asgi:application"],
            ["--proxy-headers", "--no-server-name", "orders.asgi:application"],
            ["orders.asgi:application", "--ping-interval", "30"],
        ]
        for args in cases:
            with self.subTest(args=args):
                launch = parse_daphne(args, {})
                self.assertEqual("orders.asgi:application", launch.target)
                self.assertEqual(["."], launch.search_paths)

    def test_first_valid_application_reference_wins(self):
        launch = parse_daphne(
            ["not-an-application", "orders.asgi:application", "inventory.asgi:application"], {}
        )

        self.assertEqual("orders.asgi:application", launch.target)

    def test_option_terminator_stops_option_parsing(self):
        launch = parse_daphne(["--", "--future-option", "orders.asgi:application"], {})

        self.assertEqual("orders.asgi:application", launch.target)

    def test_invalid_arguments_fail_closed(self):
        cases = [
            ["--future-option", "value", "orders.asgi:application"],
            ["--future-option=value", "orders.asgi:application"],
            ["-Z", "orders.asgi:application"],
            ["-hZ", "orders.asgi:application"],
            ["orders.asgi:application", "--future-option", "value"],
            ["--port"],
            ["--port", "--help", "orders.asgi:application"],
            ["--help=true", "orders.asgi:application"],
            ["--proxy-forwarded-address-header", "X-Forwarded-For", "orders.asgi:application"],
            ["not-an-application"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(Launch(), parse_daphne(args, {}))


if __name__ == "__main__":
    unittest.main()
