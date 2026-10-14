"""Tests for Django launch parsing."""

import unittest

from _beyla_otel.frameworks.django import parse_django


class TestDjangoParsing(unittest.TestCase):
    def test_environment_settings(self):
        launch = parse_django(["runserver"], {"DJANGO_SETTINGS_MODULE": "orders.settings"})

        self.assertEqual(("orders.settings", "module"), (launch.target, launch.target_kind))

    def test_settings_option_forms(self):
        cases = [
            (["runserver", "--settings", "orders.settings"], "orders.settings"),
            (["runserver", "--settings=orders.settings"], "orders.settings"),
            (["--settings", "src/orders/settings.py", "check"], "src/orders/settings.py"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, parse_django(args, {}).target)

    def test_last_settings_value_overrides_environment(self):
        launch = parse_django(
            ["--settings=orders.settings", "--settings", "inventory.settings"],
            {"DJANGO_SETTINGS_MODULE": "environment.settings"},
        )

        self.assertEqual("inventory.settings", launch.target)

    def test_last_python_path_is_used(self):
        launch = parse_django(
            ["--pythonpath", "/srv/first", "--pythonpath=/srv/orders", "--settings=orders.settings"],
            {},
        )

        self.assertEqual(["/srv/orders"], launch.search_paths)

    def test_absent_metadata_returns_empty_launch(self):
        launch = parse_django(["runserver"], {})

        self.assertEqual(("", "none", []), (launch.target, launch.target_kind, launch.search_paths))


if __name__ == "__main__":
    unittest.main()
