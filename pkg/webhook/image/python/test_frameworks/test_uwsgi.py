"""Tests for uWSGI launch parsing."""

import unittest

from _beyla_otel.frameworks.uwsgi import parse_uwsgi


class TestUwsgiParsing(unittest.TestCase):
    def test_module_option_forms(self):
        cases = [
            ["-w", "orders.wsgi:application"],
            ["-worders.wsgi:application"],
            ["-w=orders.wsgi:application"],
            ["--module", "orders.wsgi:application"],
            ["--module=orders.wsgi:application"],
            ["--wsgi", "orders.wsgi:application"],
        ]
        for args in cases:
            with self.subTest(args=args):
                launch = parse_uwsgi(args, {})
                self.assertEqual(("orders.wsgi:application", "module"), (launch.target, launch.target_kind))

    def test_file_option_forms(self):
        cases = [
            ["--wsgi-file", "src/orders.py"],
            ["--wsgi-file=src/orders.py"],
            ["--file", "src/orders.py"],
            ["--file=src/orders.py"],
        ]
        for args in cases:
            with self.subTest(args=args):
                launch = parse_uwsgi(args, {})
                self.assertEqual(("src/orders.py", "file"), (launch.target, launch.target_kind))

    def test_last_module_wins(self):
        launch = parse_uwsgi(
            ["--module=orders.wsgi:application", "--module", "inventory.wsgi:application"], {}
        )

        self.assertEqual("inventory.wsgi:application", launch.target)

    def test_python_paths_are_reversed(self):
        launch = parse_uwsgi(
            [
                "--pythonpath",
                "/srv/first",
                "--python-path=/srv/second",
                "--pp",
                "/srv/third",
                "--module=orders.wsgi:application",
            ],
            {},
        )

        self.assertEqual(["/srv/third", "/srv/second", "/srv/first", "."], launch.search_paths)

    def test_module_and_file_conflict_returns_empty_launch(self):
        launch = parse_uwsgi(
            ["--module=orders.wsgi:application", "--wsgi-file=src/orders.py"], {}
        )

        self.assertEqual(("", "none", []), (launch.target, launch.target_kind, launch.search_paths))

    def test_missing_option_value_returns_empty_launch(self):
        for option in ("--module", "--wsgi-file", "--pythonpath"):
            with self.subTest(option=option):
                launch = parse_uwsgi([option], {})
                self.assertEqual(("", []), (launch.target, launch.search_paths))

    def test_paths_are_available_without_an_application(self):
        launch = parse_uwsgi(["--pythonpath=/srv/orders"], {})

        self.assertEqual(("", ["/srv/orders", "."]), (launch.target, launch.search_paths))

    def test_option_value_is_not_reparsed_as_a_module_option(self):
        launch = parse_uwsgi(["--http", "--module", "orders.wsgi:application"], {})

        self.assertEqual("", launch.target)

    def test_parsing_resumes_after_an_option_value(self):
        launch = parse_uwsgi(
            ["--http", "--module", "--module", "orders.wsgi:application"],
            {},
        )

        self.assertEqual("orders.wsgi:application", launch.target)

    def test_unknown_option_before_module_fails_closed(self):
        launch = parse_uwsgi(
            ["--plugin-option", "--module", "orders.wsgi:application"],
            {},
        )

        self.assertEqual("", launch.target)

    def test_flag_does_not_hide_following_module_option(self):
        launch = parse_uwsgi(["--master", "--module", "orders.wsgi:application"], {})

        self.assertEqual("orders.wsgi:application", launch.target)


if __name__ == "__main__":
    unittest.main()
