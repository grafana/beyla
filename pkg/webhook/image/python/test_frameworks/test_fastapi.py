"""Tests for FastAPI CLI launch parsing."""

import unittest

from _beyla_otel.frameworks.fastapi import (
    FASTAPI_WITH_VALUES,
    FASTAPI_WITHOUT_VALUES,
    parse_fastapi,
)
from _beyla_otel.model import Launch


EXPECTED_WITH_VALUES = {
    "--host", "--port", "--uds", "--fd", "--app", "--entrypoint", "-e",
    "--root-path", "--forwarded-allow-ips", "--workers", "--reload-delay",
    "--reload-dir", "--reload-include", "--reload-exclude",
}
EXPECTED_WITHOUT_VALUES = {
    "--reload", "--no-reload", "--proxy-headers", "--no-proxy-headers",
    "--verbose", "-v", "--help", "-h",
}


class TestFastAPIParsing(unittest.TestCase):
    def test_every_option_with_a_value(self):
        self.assertEqual(EXPECTED_WITH_VALUES, FASTAPI_WITH_VALUES)
        for option in EXPECTED_WITH_VALUES:
            with self.subTest(option=option):
                if option in {"--entrypoint", "-e"}:
                    args = ["run", option, "orders.api:app"]
                    expected = "orders.api:app"
                else:
                    args = ["run", option, "env:prod", "orders.py"]
                    expected = "orders.py"
                self.assertEqual(expected, parse_fastapi(args, {}).target)

    def test_every_flag(self):
        self.assertEqual(EXPECTED_WITHOUT_VALUES, FASTAPI_WITHOUT_VALUES)
        for option in EXPECTED_WITHOUT_VALUES:
            with self.subTest(option=option):
                self.assertEqual("orders.py", parse_fastapi(["run", option, "orders.py"], {}).target)

    def test_file_application(self):
        launch = parse_fastapi(["run", "src/orders/main.py"], {})

        self.assertEqual(("src/orders/main.py", "file"), (launch.target, launch.target_kind))

    def test_explicit_entrypoint_forms(self):
        cases = [
            ["run", "--entrypoint", "orders.api:app"],
            ["dev", "--entrypoint=orders.api:app"],
            ["run", "-e", "orders.api:app"],
            ["run", "-eorders.api:app"],
            ["run", "-veorders.api:app"],
            ["run", "-ve", "orders.api:app"],
            ["run", "--entrypoint", "other.api:app", "--entrypoint", "orders.api:app"],
            ["run", "--proxy-headers", "--entrypoint", "orders.api:app"],
            ["--verbose", "run", "--entrypoint", "orders.api:app"],
            ["--no-verbose", "run", "--entrypoint", "orders.api:app"],
        ]
        for args in cases:
            with self.subTest(args=args):
                launch = parse_fastapi(args, {})
                self.assertEqual(("orders.api:app", "module"), (launch.target, launch.target_kind))
                self.assertEqual(["."], launch.search_paths)

    def test_automatic_discovery_without_application(self):
        for args in (["run"], ["dev", "--reload"], ["--verbose", "run"], ["--no-verbose", "dev"]):
            with self.subTest(args=args):
                self.assertTrue(parse_fastapi(args, {}).fastapi_auto)

    def test_recognized_options_are_consumed(self):
        cases = [
            ["run", "--host", "0.0.0.0", "orders.py"],
            ["run", "--port=8000", "orders.py"],
            ["run", "--workers", "-1", "orders.py"],
            ["run", "-v", "orders.py"],
            ["run", "--", "orders.py"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual("orders.py", parse_fastapi(args, {}).target)

    def test_option_value_is_not_mistaken_for_an_application(self):
        launch = parse_fastapi(["run", "--host", "orders.api:app"], {})

        self.assertTrue(launch.fastapi_auto)
        self.assertEqual("", launch.target)

    def test_app_option_disables_automatic_discovery(self):
        launch = parse_fastapi(["run", "--app", "orders.api:app"], {})

        self.assertFalse(launch.fastapi_auto)
        self.assertEqual("", launch.target)

    def test_invalid_arguments_fail_closed(self):
        cases = [
            ["serve", "orders.py"],
            ["run", "--future-option", "value", "orders.py"],
            ["run", "--future-option=value", "orders.py"],
            ["run", "--reload=true", "orders.py"],
            ["run", "--port"],
            ["run", "-Z", "orders.py"],
            ["run", "orders.py", "--future-option"],
            ["run", "--no-verbose", "orders.py"],
            ["run", "orders.py", "inventory.py"],
            ["run", "--entrypoint="],
            ["run", "--entrypoint", "orders.api"],
            ["run", "--entrypoint", " orders.api:app "],
            ["run", "--entrypoint", "orders.api:create()"],
            ["run", "--entrypoint", "orders.api:app", "orders.py"],
            ["run", "--entrypoint", "orders.api:app", "--app", "ignored"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual(Launch(), parse_fastapi(args, {}))

    def test_entrypoint_like_option_values_enable_automatic_discovery(self):
        cases = [
            ["run", "--root-path", "--entrypoint=orders.api:app"],
            ["run", "--root-path", "-eorders.api:app"],
        ]
        for args in cases:
            with self.subTest(args=args):
                launch = parse_fastapi(args, {})
                self.assertEqual("", launch.target)
                self.assertTrue(launch.fastapi_auto)


if __name__ == "__main__":
    unittest.main()
