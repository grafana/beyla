"""Tests for Flask launch parsing."""

import unittest

from _beyla_otel.frameworks.flask import parse_flask


class TestFlaskParsing(unittest.TestCase):
    def test_environment_application(self):
        launch = parse_flask(["run"], {"FLASK_APP": "orders.web:app"})

        self.assertEqual(("orders.web:app", "module"), (launch.target, launch.target_kind))
        self.assertEqual(["."], launch.search_paths)

    def test_command_line_application_forms(self):
        cases = [
            ["--app", "orders.web:app", "run"],
            ["--app=orders.web:app", "run"],
            ["-A", "orders.web:app", "run"],
            ["-Aorders.web:app", "run"],
            ["-A=orders.web:app", "run"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertEqual("orders.web:app", parse_flask(args, {}).target)

    def test_command_line_application_overrides_environment(self):
        launch = parse_flask(
            ["--app", "orders.web:app", "run"], {"FLASK_APP": "environment.web:app"}
        )

        self.assertEqual("orders.web:app", launch.target)

    def test_file_application_has_no_module_search_path(self):
        launch = parse_flask(["--app=src/orders.py", "run"], {})

        self.assertEqual(("src/orders.py", "file", []), (launch.target, launch.target_kind, launch.search_paths))

    def test_absent_application_enables_automatic_discovery(self):
        launch = parse_flask(["run"], {})

        self.assertTrue(launch.flask_auto)

    def test_option_terminator_ignores_following_application_options(self):
        launch = parse_flask(["--", "--app=orders.web:app", "run"], {})

        self.assertEqual("", launch.target)
        self.assertTrue(launch.flask_auto)


if __name__ == "__main__":
    unittest.main()
