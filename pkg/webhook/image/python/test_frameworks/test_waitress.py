"""Tests for Waitress launch parsing."""

import unittest

from _beyla_otel.frameworks.waitress import (
    WAITRESS_WITH_VALUES,
    WAITRESS_WITHOUT_VALUES,
    parse_waitress,
)
from _beyla_otel.model import Launch


EXPECTED_WITH_VALUES = set("""
--host --port --listen --threads --trusted-proxy --trusted-proxy-count
--trusted-proxy-headers --url-scheme --url-prefix --backlog --recv-bytes --send-bytes
--outbuf-overflow --outbuf-high-watermark --inbuf-overflow --connection-limit
--cleanup-interval --channel-timeout --max-request-header-size --max-request-body-size
--ident --asyncore-loop-timeout --unix-socket --unix-socket-perms --sockets
--channel-request-lookahead --server-name --app
""".split())
EXPECTED_WITHOUT_VALUES = set("""
--help --call --ipv4 --no-ipv4 --ipv6 --no-ipv6 --log-untrusted-proxy-headers
--no-log-untrusted-proxy-headers --clear-untrusted-proxy-headers
--no-clear-untrusted-proxy-headers --log-socket-errors --no-log-socket-errors
--expose-tracebacks --no-expose-tracebacks --asyncore-use-poll --no-asyncore-use-poll
""".split())


class TestWaitressParsing(unittest.TestCase):
    def test_every_option_with_a_value(self):
        self.assertEqual(EXPECTED_WITH_VALUES, WAITRESS_WITH_VALUES)
        for option in EXPECTED_WITH_VALUES:
            with self.subTest(option=option):
                args = [option, "orders.wsgi:application"]
                if option != "--app":
                    args = [option, "env:prod", "orders.wsgi:application"]
                launch = parse_waitress(args, {})
                self.assertEqual("orders.wsgi:application", launch.target)

    def test_every_flag(self):
        self.assertEqual(EXPECTED_WITHOUT_VALUES, WAITRESS_WITHOUT_VALUES)
        for option in EXPECTED_WITHOUT_VALUES:
            with self.subTest(option=option):
                launch = parse_waitress([option, "orders.wsgi:application"], {})
                self.assertEqual("orders.wsgi:application", launch.target)

    def test_application_reference(self):
        launch = parse_waitress(["orders.wsgi:application"], {})

        self.assertEqual(("orders.wsgi:application", "module"), (launch.target, launch.target_kind))

    def test_dotted_application_reference(self):
        cases = [
            ["orders.wsgi.application"],
            ["--call", "orders.wsgi.application"],
            ["--call", "--app=orders.wsgi.application"],
        ]
        for args in cases:
            with self.subTest(args=args):
                launch = parse_waitress(args, {})
                self.assertEqual(
                    ("orders.wsgi.application", "dotted_reference"),
                    (launch.target, launch.target_kind),
                )

    def test_app_option_forms(self):
        cases = [
            (["--app", "orders.wsgi:application"], "orders.wsgi:application"),
            (["--app=orders.wsgi:application"], "orders.wsgi:application"),
            (["--call", "--app=orders.wsgi:create"], "orders.wsgi:create"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, parse_waitress(args, {}).target)

    def test_recognized_options_are_consumed(self):
        cases = [
            ["--host", "0.0.0.0", "orders.wsgi:application"],
            ["--port=8000", "orders.wsgi:application"],
            ["--channel-timeout", "-1", "orders.wsgi:application"],
            ["--ident", "-", "orders.wsgi:application"],
            ["--ident=--private", "orders.wsgi:application"],
            ["--listen", "*:8000", "--listen=[::1]:8000", "orders.wsgi:application"],
            ["--ipv4", "--no-ipv6", "orders.wsgi:application"],
            ["--app", "orders.wsgi:application", "--threads", "4"],
            ["--", "orders.wsgi:application"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual("orders.wsgi:application", parse_waitress(args, {}).target)

    def test_invalid_arguments_fail_closed(self):
        cases = [
            [],
            ["--future-option", "value", "orders.wsgi:application"],
            ["--future-option=value", "orders.wsgi:application"],
            ["-p", "8000", "orders.wsgi:application"],
            ["--port"],
            ["--ipv4=true", "orders.wsgi:application"],
            ["--ident", "--future-option", "value", "orders.wsgi:application"],
            ["orders.wsgi:application", "--port=8000"],
            ["orders.wsgi:application", "inventory.wsgi:application"],
            ["--app=orders.wsgi:application", "inventory.wsgi:application"],
            ["--thre=4", "orders.wsgi:application"],
            ["--adj", "value", "orders.wsgi:application"],
            ["--version", "orders.wsgi:application"],
            ["--call", "orders.wsgi:create()"],
            [" orders.wsgi:application "],
            ["orders"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(Launch(), parse_waitress(args, {}))


if __name__ == "__main__":
    unittest.main()
