"""Tests for shared framework target parsing."""

import unittest

from _beyla_otel.frameworks.common import (
    application_reference,
    classify_target,
    clean_value,
    first_application_reference,
    target_name,
    target_reference,
    valid_identifier,
    valid_module,
)


class TestCommonParsing(unittest.TestCase):
    def test_target_name(self):
        cases = {
            "company.orders.api:app": "orders",
            "orders.wsgi:application": "orders",
            "company.orders.settings.production": "orders",
            "company.orders.tasks": "orders",
            "src/orders_service.py": "orders_service",
            "app.main:app": "main",
            "main.py": "main",
            "config.settings": "",
            "src/orders/__init__.py": "",
            "company.inventory.application:create()": "inventory",
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(expected, target_name(target))

    def test_clean_value(self):
        cases = {
            "orders": "orders",
            "  orders  ": "orders",
            "": "",
            "   ": "",
            "ord\x01ers": "",
            "orders\n": "orders",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(expected, clean_value(value))

    def test_valid_identifier(self):
        cases = {
            "": False,
            "a": True,
            "_": True,
            "a1": True,
            "_1": True,
            "1a": False,
            "a_b": True,
            "a-b": False,
            "ab c": False,
            "café": True,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(expected, valid_identifier(value))

    def test_valid_module(self):
        cases = {
            "": False,
            "a": True,
            "_a1": True,
            "a.b": True,
            "a..b": False,
            "a.": False,
            ".a": False,
            "1a.b": False,
            "a-b": False,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(expected, valid_module(value))

    def test_application_references(self):
        accepted = [
            "app:main",
            "company.orders.api:app",
            "app:main.attr",
            "app:create()",
            "app:create(a=1,b=2)",
            "app:create('redis://cache:6379/0')",
        ]
        rejected = [
            "",
            "app",
            "app:",
            ":app",
            "app:main:extra",
            "app::main",
            "1app:main",
            "app:1main",
            "app:create (a=1)",
        ]

        for value in accepted:
            with self.subTest(value=value):
                self.assertTrue(application_reference(value))
        for value in rejected:
            with self.subTest(value=value):
                self.assertFalse(application_reference(value))

    def test_strict_application_reference_rejects_factory_calls(self):
        self.assertTrue(application_reference("app:create", strict=True))
        self.assertFalse(application_reference("app:create()", strict=True))
        self.assertFalse(
            application_reference("app:create('redis://cache:6379/0')", strict=True)
        )

    def test_first_application_reference(self):
        values = ["orders", "app:", "orders.api:app", "inventory.wsgi:application"]

        self.assertEqual("orders.api:app", first_application_reference(values))
        self.assertEqual("", first_application_reference([]))

    def test_target_reference(self):
        self.assertEqual("company.orders.api", target_reference(" company.orders.api:app "))

    def test_classify_target(self):
        cases = {
            "": "none",
            "orders.api:app": "module",
            "orders.py": "file",
            "src/orders.py:app": "file",
            "/srv/orders.py": "file",
            "src\\orders.py": "file",
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                self.assertEqual(expected, classify_target(target))


if __name__ == "__main__":
    unittest.main()
