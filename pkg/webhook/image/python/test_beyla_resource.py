"""Tests for applying detected metadata to SDK resources."""

import unittest

from _beyla_otel.model import ProjectMetadata
from _beyla_otel.resource import initialize_with_resource_detection


class FakeResource:
    defaults = {"service.name": "unknown_service:python"}

    def __init__(self, attributes=None, schema_url=None):
        self.attributes = dict(attributes or {})
        self.schema_url = schema_url

    @staticmethod
    def create(attributes=None, schema_url=None):
        values = dict(FakeResource.defaults)
        values.update(attributes or {})
        return FakeResource(values, schema_url)

    def merge(self, other):
        values = dict(self.attributes)
        values.update(other.attributes)
        return FakeResource(values, self.schema_url)


class TestResourceDetection(unittest.TestCase):
    def setUp(self):
        FakeResource.defaults = {"service.name": "unknown_service:python"}

    def initialize(self, resolver, attributes=None, failure=None):
        result = {}

        def sdk_initialize():
            result["resource"] = FakeResource.create(attributes)
            if failure:
                raise failure

        initialize_with_resource_detection(sdk_initialize, FakeResource, resolver)
        return result["resource"]

    def test_missing_values_are_detected(self):
        resource = self.initialize(
            lambda: ProjectMetadata(
                name="orders",
                version="1.2.3",
                name_source="launch target",
                version_source="pyproject.toml",
            )
        )

        self.assertEqual("orders", resource.attributes["service.name"])
        self.assertEqual("1.2.3", resource.attributes["service.version"])

    def test_existing_values_and_namespace_are_preserved(self):
        resource = self.initialize(
            lambda: ProjectMetadata(name="detected", version="9"),
            {
                "service.name": "configured",
                "service.version": "2",
                "service.namespace": "production",
            },
        )

        self.assertEqual("configured", resource.attributes["service.name"])
        self.assertEqual("2", resource.attributes["service.version"])
        self.assertEqual("production", resource.attributes["service.namespace"])

    def test_existing_name_can_receive_detected_version(self):
        resource = self.initialize(
            lambda: ProjectMetadata(version="3", version_source="setup.cfg"),
            {"service.name": "configured"},
        )

        self.assertEqual("configured", resource.attributes["service.name"])
        self.assertEqual("3", resource.attributes["service.version"])

    def test_detector_runs_once_for_multiple_resources(self):
        calls = []
        resources = []

        def resolver():
            calls.append(True)
            return ProjectMetadata(name="orders", name_source="launch target")

        def sdk_initialize():
            resources.append(FakeResource.create())
            resources.append(FakeResource.create())

        initialize_with_resource_detection(sdk_initialize, FakeResource, resolver)

        self.assertEqual(1, len(calls))
        self.assertEqual(["orders", "orders"], [item.attributes["service.name"] for item in resources])

    def test_original_create_is_restored_after_success(self):
        original = FakeResource.__dict__["create"]

        self.initialize(lambda: ProjectMetadata())

        self.assertIs(original, FakeResource.__dict__["create"])

    def test_original_create_is_restored_after_failure(self):
        original = FakeResource.__dict__["create"]

        with self.assertRaisesRegex(RuntimeError, "failed"):
            self.initialize(lambda: ProjectMetadata(), failure=RuntimeError("failed"))

        self.assertIs(original, FakeResource.__dict__["create"])

    def test_detection_failure_does_not_block_initialization(self):
        def resolver():
            raise OSError("unreadable")

        resource = self.initialize(resolver)

        self.assertEqual("unknown_service:python", resource.attributes["service.name"])

    def test_enrichment_failure_does_not_block_initialization(self):
        resource = self.initialize(lambda: None)

        self.assertEqual("unknown_service:python", resource.attributes["service.name"])

    def test_unsupported_resource_class_uses_normal_initialization(self):
        initialized = []

        class UnsupportedResource:
            pass

        initialize_with_resource_detection(
            lambda: initialized.append(True),
            UnsupportedResource,
            lambda: ProjectMetadata(name="orders"),
        )

        self.assertEqual([True], initialized)


if __name__ == "__main__":
    unittest.main()
