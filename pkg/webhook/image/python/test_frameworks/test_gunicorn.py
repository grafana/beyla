"""Tests for Gunicorn launch parsing."""

import unittest

from _beyla_otel.frameworks.gunicorn import (
    GUNICORN_WITH_VALUES,
    GUNICORN_WITHOUT_VALUES,
    parse_gunicorn,
)
from _beyla_otel.model import Launch


EXPECTED_WITH_VALUES = set("""
-c --config -b --bind --backlog -w --workers -k --worker-class --threads
--worker-connections --max-requests --max-requests-jitter -t --timeout --graceful-timeout
--keep-alive --limit-request-line --limit-request-fields --limit-request-field_size
--reload-engine --reload-extra-file --chdir -e --env -p --pid --worker-tmp-dir
-u --user -g --group -m --umask --forwarded-allow-ips --access-logfile
--access-logformat --error-logfile --log-file --log-level --logger-class --log-config
--log-config-json --log-syslog-to --log-syslog-prefix --log-syslog-facility --statsd-host
--dogstatsd-tags --statsd-prefix -n --name --pythonpath --paste --paster
--proxy-allow-from --protocol --uwsgi-allow-from --keyfile --certfile --ssl-version
--cert-reqs --ca-certs --ciphers --http-protocols --http2-cleartext
--http2-max-concurrent-streams --http2-initial-window-size --http2-max-frame-size
--http2-max-header-list-size --paste-global --forwarder-headers --header-map --asgi-loop
--asgi-lifespan --asgi-disconnect-grace-period --http-parser --root-path --dirty-app
--dirty-workers --dirty-timeout --dirty-threads --dirty-graceful-timeout --control-socket
--control-socket-mode
""".split())
EXPECTED_WITHOUT_VALUES = set("""
--reload --spew --check-config --print-config --preload --no-sendfile --reuse-port
-D --daemon --initgroups --disable-redirect-access-to-syslog --capture-output
--log-syslog -R --enable-stdio-inheritance --enable-backlog-metric --suppress-ragged-eofs
--do-handshake-on-connect --permit-obsolete-folding --strip-header-spaces
--permit-unconventional-http-method --permit-unconventional-http-version --casefold-http-method
--no-control-socket -h --help -v --version --proxy-protocol
""".split())


class TestGunicornParsing(unittest.TestCase):
    def test_every_option_with_a_value(self):
        self.assertEqual(EXPECTED_WITH_VALUES, GUNICORN_WITH_VALUES)
        for option in EXPECTED_WITH_VALUES:
            with self.subTest(option=option):
                launch = parse_gunicorn(
                    [option, "env:prod", "orders.wsgi:application"], {}
                )
                self.assertEqual("orders.wsgi:application", launch.target)

    def test_every_flag(self):
        self.assertEqual(EXPECTED_WITHOUT_VALUES, GUNICORN_WITHOUT_VALUES)
        for option in EXPECTED_WITHOUT_VALUES:
            with self.subTest(option=option):
                launch = parse_gunicorn([option, "orders.wsgi:application"], {})
                self.assertEqual("orders.wsgi:application", launch.target)

    def test_application_forms(self):
        targets = (
            "orders.wsgi",
            "orders.wsgi:application",
            "orders.wsgi:create()",
            "orders.wsgi:create('redis://cache:6379/0')",
        )
        for target in targets:
            with self.subTest(target=target):
                launch = parse_gunicorn([target], {})
                self.assertEqual((target, "module"), (launch.target, launch.target_kind))

    def test_environment_and_command_line_precedence(self):
        launch = parse_gunicorn(
            ["--chdir", "/srv/orders", "--name=cli-name", "orders.wsgi:application"],
            {
                "GUNICORN_CMD_ARGS": (
                    "--chdir '/srv/default app' --pythonpath=lib,../shared --name env-name"
                )
            },
        )

        self.assertEqual("/srv/orders", launch.app_dir)
        self.assertEqual(["/srv/orders/../shared", "/srv/orders/lib", "/srv/orders"], launch.search_paths)
        self.assertEqual("cli-name", launch.fallback_name)

    def test_name_option_forms(self):
        cases = [
            (["-n", "orders", "orders.wsgi:application"], "orders"),
            (["-norders", "orders.wsgi:application"], "orders"),
            (["-n=orders", "orders.wsgi:application"], "orders"),
            (["-Dnorders", "orders.wsgi:application"], "orders"),
            (["--name", "orders", "orders.wsgi:application"], "orders"),
            (["--name=orders", "orders.wsgi:application"], "orders"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, parse_gunicorn(args, {}).fallback_name)

    def test_recognized_option_forms(self):
        cases = [
            ["--bind", ":8000", "orders.wsgi:application"],
            ["--bind=:8000", "orders.wsgi:application"],
            ["-b", ":8000", "orders.wsgi:application"],
            ["-b:8000", "orders.wsgi:application"],
            ["-Dw", "4", "orders.wsgi:application"],
            ["-Dw4", "orders.wsgi:application"],
            ["--preload", "orders.wsgi:application"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual("orders.wsgi:application", parse_gunicorn(args, {}).target)

    def test_proxy_protocol_modes(self):
        cases = [
            ["--proxy-protocol", "off", "orders.wsgi:application"],
            ["--proxy-protocol", "v1", "orders.wsgi:application"],
            ["--proxy-protocol", "orders.wsgi:application"],
            ["--proxy-protocol", "v2", "orders.wsgi:application"],
            ["--proxy-protocol=auto", "orders.wsgi:application"],
            ["orders.wsgi:application", "--proxy-protocol"],
            ["--proxy-protocol", "--dogstatsd-tags", "env:prod", "orders.wsgi:application"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual("orders.wsgi:application", parse_gunicorn(args, {}).target)

    def test_option_terminator_stops_option_parsing(self):
        launch = parse_gunicorn(["--", "orders.wsgi:application", "--future-option"], {})

        self.assertEqual("orders.wsgi:application", launch.target)

    def test_option_terminator_stops_setting_collection(self):
        launch = parse_gunicorn(["orders.wsgi:application", "--", "--name", "wrong"], {})

        self.assertEqual("", launch.fallback_name)

    def test_invalid_arguments_fail_closed(self):
        cases = [
            ["--future-option", "value", "orders.wsgi:application"],
            ["--future-option=value", "orders.wsgi:application"],
            ["-Z", "orders.wsgi:application"],
            ["-DZ", "orders.wsgi:application"],
            ["orders.wsgi:application", "--future-option", "value"],
            ["--future-option", "--capture-output", "orders.wsgi:application"],
            ["--bind"],
            ["--preload=true", "orders.wsgi:application"],
            ["--proxy-protocol=invalid", "orders.wsgi:application"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(Launch(), parse_gunicorn(args, {}))

    def test_invalid_application_is_not_used_as_a_target(self):
        launch = parse_gunicorn(["not-an-application"], {})

        self.assertEqual("", launch.target)
        self.assertEqual(["."], launch.search_paths)

    def test_malformed_environment_arguments_fail_closed(self):
        cases = [
            "--chdir 'unterminated",
            "--name trailing\\",
            "--future-option value",
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    Launch(),
                    parse_gunicorn(
                        ["orders.wsgi:application"], {"GUNICORN_CMD_ARGS": value}
                    ),
                )


if __name__ == "__main__":
    unittest.main()
