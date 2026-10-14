"""Tests for Uvicorn launch parsing."""

import unittest

from _beyla_otel.frameworks.uvicorn import (
    UVICORN_WITH_VALUES,
    UVICORN_WITHOUT_VALUES,
    parse_uvicorn,
)
from _beyla_otel.model import Launch


EXPECTED_WITH_VALUES = set("""
--host --port --uds --fd --reload-dir --reload-delay --reload-include --reload-exclude
--workers --env-file --timeout-worker-healthcheck --log-config --log-level --loop --http
--ws --ws-max-size --ws-max-queue --ws-ping-interval --ws-ping-timeout --ws-per-message-deflate
--lifespan --h11-max-incomplete-event-size --interface --root-path --forwarded-allow-ips --header
--ssl-keyfile --ssl-keyfile-password --ssl-certfile --ssl-version --ssl-cert-reqs --ssl-ca-certs
--ssl-ciphers --app-dir --limit-concurrency --backlog --limit-max-requests
--limit-max-requests-jitter --timeout-keep-alive --timeout-graceful-shutdown
""".split())
EXPECTED_WITHOUT_VALUES = set("""
--reload --access-log --no-access-log --use-colors --no-use-colors --proxy-headers
--no-proxy-headers --server-header --no-server-header --date-header --no-date-header
--version --reset-contextvars --factory --help
""".split())


class TestUvicornParsing(unittest.TestCase):
    def test_every_option_with_a_value(self):
        self.assertEqual(EXPECTED_WITH_VALUES, UVICORN_WITH_VALUES)
        for option in EXPECTED_WITH_VALUES:
            with self.subTest(option=option):
                launch = parse_uvicorn([option, "env:prod", "orders.api:app"], {})
                self.assertEqual("orders.api:app", launch.target)

    def test_every_flag(self):
        self.assertEqual(EXPECTED_WITHOUT_VALUES, UVICORN_WITHOUT_VALUES)
        for option in EXPECTED_WITHOUT_VALUES:
            with self.subTest(option=option):
                launch = parse_uvicorn([option, "orders.api:app"], {})
                self.assertEqual("orders.api:app", launch.target)

    def test_command_line_application(self):
        launch = parse_uvicorn(["orders.api:app"], {})

        self.assertEqual(("orders.api:app", "module"), (launch.target, launch.target_kind))

    def test_environment_application_and_directory(self):
        launch = parse_uvicorn(
            [], {"UVICORN_APP": " orders.api:app ", "UVICORN_APP_DIR": "/srv/orders"}
        )

        self.assertEqual("orders.api:app", launch.target)
        self.assertEqual(("/srv/orders", ["/srv/orders"]), (launch.app_dir, launch.search_paths))

    def test_command_line_application_and_directory_override_environment(self):
        launch = parse_uvicorn(
            ["--app-dir=/srv/orders", "orders.api:app"],
            {"UVICORN_APP": "environment.api:app", "UVICORN_APP_DIR": "/srv/environment"},
        )

        self.assertEqual("orders.api:app", launch.target)
        self.assertEqual("/srv/orders", launch.app_dir)

    def test_last_application_directory_wins(self):
        launch = parse_uvicorn(
            ["--app-dir", "/srv/first", "--app-dir=/srv/orders", "orders.api:app"], {}
        )

        self.assertEqual(("/srv/orders", ["/srv/orders"]), (launch.app_dir, launch.search_paths))

    def test_first_valid_application_reference_wins(self):
        launch = parse_uvicorn(
            ["not-an-application", "orders.api:app", "inventory.api:app"], {}
        )

        self.assertEqual("orders.api:app", launch.target)

    def test_recognized_option_forms(self):
        cases = [
            ["--host", "0.0.0.0", "orders.api:app"],
            ["--port=8000", "orders.api:app"],
            ["--workers", "-1", "orders.api:app"],
            ["--reload", "--no-access-log", "orders.api:app"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual("orders.api:app", parse_uvicorn(args, {}).target)

    def test_option_terminator_stops_option_parsing(self):
        launch = parse_uvicorn(["--", "--future-option", "orders.api:app"], {})

        self.assertEqual("orders.api:app", launch.target)

    def test_option_terminator_stops_application_directory_parsing(self):
        launch = parse_uvicorn(
            ["orders.api:app", "--", "--app-dir", "/wrong"],
            {"UVICORN_APP_DIR": "/srv/orders"},
        )

        self.assertEqual(["/srv/orders"], launch.search_paths)

    def test_invalid_arguments_fail_closed(self):
        cases = [
            ["--future-option", "value", "orders.api:app"],
            ["--future-option=value", "orders.api:app"],
            ["-Z", "orders.api:app"],
            ["orders.api:app", "--future-option", "value"],
            ["--port"],
            ["--reload=true", "orders.api:app"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(Launch(), parse_uvicorn(args, {}))

    def test_invalid_arguments_reject_environment_application(self):
        launch = parse_uvicorn(
            ["--future-option", "value"], {"UVICORN_APP": "orders.api:app"}
        )

        self.assertEqual(Launch(), launch)


if __name__ == "__main__":
    unittest.main()
