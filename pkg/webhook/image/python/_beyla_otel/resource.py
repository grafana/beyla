"""Apply Python service metadata to auto-instrumentation resources."""

from .log import info, warning
from .metadata import detect_service_metadata
from .model import ProjectMetadata


SERVICE_NAME = "service.name"
SERVICE_VERSION = "service.version"
_UNRESOLVED = object()


def initialize_with_resource_detection(initialize, resource_class=None, resolver=None):
    """Initialize OpenTelemetry while temporarily enriching created resources."""
    resource_class = resource_class or _load_sdk_resource()
    if resource_class is None:
        return initialize()
    wrapped = _resource_create_wrapper(resource_class, resolver or detect_service_metadata)
    if wrapped is None:
        return initialize()
    descriptor, create = wrapped
    try:
        resource_class.create = staticmethod(create)
    except Exception as error:
        warning("service metadata detector could not wrap the SDK resource API: {}".format(error))
        return initialize()
    try:
        return initialize()
    finally:
        resource_class.create = descriptor


def _load_sdk_resource():
    """Load the SDK resource class after warming its configuration module."""
    try:
        import opentelemetry.sdk._configuration  # noqa: F401
        from opentelemetry.sdk.resources import Resource
        return Resource
    except Exception as error:
        warning("service metadata detector could not load the SDK resource API: {}".format(error))
        return None


def _resource_create_wrapper(resource_class, resolver):
    """Build a guarded temporary Resource.create replacement."""
    try:
        descriptor = resource_class.__dict__["create"]
        original_create = resource_class.create
    except Exception as error:
        warning("service metadata detector could not wrap the SDK resource API: {}".format(error))
        return None
    fallback = _ResourceFallback(resource_class, resolver)
    enrichment_warning = []

    def create(attributes=None, schema_url=None):
        """Create an SDK resource and add only missing service metadata."""
        resource = original_create(attributes, schema_url)
        try:
            return fallback.apply(resource)
        except Exception as error:
            if not enrichment_warning:
                warning("service metadata enrichment failed: {}".format(error))
                enrichment_warning.append(True)
            return resource

    return descriptor, create


class _ResourceFallback:
    """Cache detected metadata and merge it into SDK resources."""

    def __init__(self, resource_class, resolver):
        """Create a lazy resource fallback."""
        self.resource_class = resource_class
        self.resolver = resolver
        self.metadata = _UNRESOLVED
        self.logged_existing_name = False
        self.logged_missing_name = False
        self.logged_missing_result = False
        self.logged_selected_name = False
        self.logged_selected_version = False

    def apply(self, resource):
        """Merge detected values only where the SDK resource is missing them."""
        attributes = resource.attributes
        name = attributes.get(SERVICE_NAME)
        missing_name = _missing_service_name(name)
        missing_version = not attributes.get(SERVICE_VERSION)
        self._log_name_state(name, missing_name)
        if not missing_name and not missing_version:
            return resource

        metadata = self._resolve()
        updates = self._updates(metadata, missing_name, missing_version)
        if not updates:
            return resource
        detected = self.resource_class(updates, resource.schema_url)
        return resource.merge(detected)

    def _resolve(self):
        """Run application metadata detection once."""
        if self.metadata is not _UNRESOLVED:
            return self.metadata
        try:
            metadata = self.resolver()
            self.metadata = metadata if metadata is not None else ProjectMetadata()
        except Exception as error:
            warning("service metadata detection failed: {}".format(error))
            self.metadata = ProjectMetadata()
        return self.metadata

    def _updates(self, metadata, missing_name, missing_version):
        """Select detected attributes that remain missing."""
        updates = {}
        if missing_name and metadata.name:
            updates[SERVICE_NAME] = metadata.name
            if not self.logged_selected_name:
                info("service.name detected from {}: {}; using it".format(metadata.name_source, metadata.name))
                self.logged_selected_name = True
        elif missing_name and not self.logged_missing_result:
            info("service.name was not found in Python application metadata; keeping the SDK default")
            self.logged_missing_result = True
        if missing_version and metadata.version:
            updates[SERVICE_VERSION] = metadata.version
            if not self.logged_selected_version:
                info("service.version detected from {}: {}; using it".format(metadata.version_source, metadata.version))
                self.logged_selected_version = True
        return updates

    def _log_name_state(self, name, missing):
        """Log whether local name detection is necessary."""
        if missing and not self.logged_missing_name:
            info("service.name was not found by OpenTelemetry resource detectors; looking at Python application metadata")
            self.logged_missing_name = True
        elif not missing and not self.logged_existing_name:
            info("service.name was provided by OpenTelemetry resource detectors: {}; keeping it".format(name))
            self.logged_existing_name = True


def _missing_service_name(value):
    """Treat the SDK's generated unknown service name as missing."""
    return not value or value == "unknown_service" or str(value).startswith("unknown_service:")
