"""Tests for Celery launch parsing."""

import unittest

from _beyla_otel.frameworks.celery import parse_celery


class TestCeleryParsing(unittest.TestCase):
    def test_environment_application(self):
        launch = parse_celery(["worker"], {"CELERY_APP": "orders.tasks"})

        self.assertEqual(("orders.tasks", "module"), (launch.target, launch.target_kind))

    def test_command_line_application_forms(self):
        cases = [
            (["-A", "orders.tasks", "worker"], "orders.tasks"),
            (["--app", "orders.tasks", "worker"], "orders.tasks"),
            (["-Aorders.tasks", "worker"], "orders.tasks"),
            (["-A=orders.tasks", "worker"], "orders.tasks"),
            (["--app=orders.tasks", "worker"], "orders.tasks"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(expected, parse_celery(args, {}).target)

    def test_last_command_line_application_wins(self):
        launch = parse_celery(
            ["-A", "orders.tasks", "worker", "--app=inventory.tasks"],
            {"CELERY_APP": "environment.tasks"},
        )

        self.assertEqual("inventory.tasks", launch.target)

    def test_file_application_is_classified(self):
        launch = parse_celery(["worker", "--app=src/tasks.py"], {})

        self.assertEqual(("src/tasks.py", "file"), (launch.target, launch.target_kind))

    def test_missing_application_keeps_environment_value(self):
        launch = parse_celery(["--app"], {"CELERY_APP": "orders.tasks"})

        self.assertEqual("orders.tasks", launch.target)


if __name__ == "__main__":
    unittest.main()
