"""Tests for shared framework argument parsing."""

import unittest

from _beyla_otel.frameworks.arguments import (
    argparse_application,
    argparse_positionals,
    last_long_option,
    separated_option_value,
    short_option,
)


WITH_VALUES = {"-p", "--port", "-b", "--bind"}
WITHOUT_VALUES = {"-h", "--help", "-v", "--verbose"}


class TestArgumentParsing(unittest.TestCase):
    def test_separated_option_value(self):
        cases = {
            "app": True,
            "-": True,
            "-1": True,
            "-12": True,
            "-1.5": True,
            "-1.": False,
            "-.5": True,
            "-a": False,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(expected, separated_option_value(value))

    def test_short_option_clusters(self):
        cases = [
            ("-h", (False, True)),
            ("-hv", (False, True)),
            ("-p", (True, True)),
            ("-hp", (True, True)),
            ("-p8000", (False, True)),
            ("-Z", (False, False)),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(expected, short_option(value, WITH_VALUES, WITHOUT_VALUES))

    def test_argparse_positionals(self):
        cases = [
            (["--port", "8000", "app:server"], ["app:server"]),
            (["--port=8000", "app:server"], ["app:server"]),
            (["-p8000", "app:server"], ["app:server"]),
            (["-hp", "8000", "app:server"], ["app:server"]),
            (["-", "app:server"], ["-", "app:server"]),
            (["--", "-p", "-Z", "app:server"], ["-p", "-Z", "app:server"]),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, argparse_positionals(args, WITH_VALUES, WITHOUT_VALUES))

    def test_argparse_positionals_fail_closed(self):
        cases = [
            ["--port"],
            ["--help=true", "app:server"],
            ["--future", "app:server"],
            ["--future=x", "app:server"],
            ["-Z", "app:server"],
            ["--port", "--help", "app:server"],
        ]
        for args in cases:
            with self.subTest(args=args):
                self.assertIsNone(argparse_positionals(args, WITH_VALUES, WITHOUT_VALUES))

    def test_argparse_application(self):
        launch = argparse_application(
            ["--port", "8000", "not-a-reference", "orders.api:app", "inventory.wsgi:application"],
            WITH_VALUES,
            WITHOUT_VALUES,
        )

        self.assertEqual("orders.api:app", launch.target)
        self.assertEqual(["."], launch.search_paths)

    def test_last_long_option(self):
        cases = [
            (["--other", "value"], "initial", "initial"),
            (["--target", "a", "--target", "b"], "", "b"),
            (["--target", "a", "--target=attached"], "", "attached"),
            (["--target"], "initial", "initial"),
            (["--targets=2"], "initial", "initial"),
        ]
        for args, initial, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, last_long_option(args, "--target", initial))


if __name__ == "__main__":
    unittest.main()

