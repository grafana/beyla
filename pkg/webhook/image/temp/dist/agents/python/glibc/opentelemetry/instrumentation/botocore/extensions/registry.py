# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Callable, Mapping, Optional

from opentelemetry._logs import get_logger
from opentelemetry.instrumentation.botocore.extensions.types import (
    _AwsSdkCallContext,
    _AwsSdkExtension,
)
from opentelemetry.instrumentation.botocore.utils import _safe_invoke
from opentelemetry.instrumentation.botocore.version import __version__
from opentelemetry.metrics import get_meter
from opentelemetry.trace import get_tracer

if TYPE_CHECKING:
    from opentelemetry._logs import Logger, LoggerProvider
    from opentelemetry.metrics import Instrument, Meter, MeterProvider
    from opentelemetry.trace import Tracer, TracerProvider


_logger = logging.getLogger(__name__)


class ExtensionRegistry:
    """
    Registry for AWS SDK extensions that manages extension lookup and
    associated OpenTelemetry instrumentation components (tracers, loggers, meters, metrics).
    """

    def __init__(
        self,
        package_name: str,
        extensions: Mapping[str, Callable[[], type[_AwsSdkExtension]]],
        tracer_provider: Optional[TracerProvider] = None,
        logger_provider: Optional[LoggerProvider] = None,
        meter_provider: Optional[MeterProvider] = None,
    ):
        self._package_name = package_name
        self._extensions: Mapping[
            str, Callable[[], type[_AwsSdkExtension]]
        ] = extensions
        self._tracer_provider: TracerProvider = tracer_provider
        self._logger_provider: LoggerProvider = logger_provider
        self._meter_provider: MeterProvider = meter_provider
        self._tracers: dict[str, Tracer] = {}
        self._loggers: dict[str, Logger] = {}
        self._meters: dict[str, Meter] = {}
        self._metrics: dict[str, dict[str, Instrument]] = {}

    def get_extension(
        self, call_context: _AwsSdkCallContext
    ) -> _AwsSdkExtension:
        """
        Get the appropriate extension for a given call context.

        Args:
            call_context: The AWS SDK call context

        Returns:
            The matching extension for the service/operation
        """
        try:
            loader: Callable[[], type[_AwsSdkExtension]] = (
                self._extensions.get(call_context.service)
            )
            if loader is None:
                return _AwsSdkExtension(call_context)
            extension_cls = loader()
            return extension_cls(call_context)
        except Exception as exc:  # pylint: disable=broad-except
            _logger.error("Error when loading extension: %s", exc)
            return _AwsSdkExtension(call_context)

    def has_extension(self, call_context: _AwsSdkCallContext) -> bool:
        """
        Check if a dedicated extension exists for the given call context.

        Args:
            call_context: The AWS SDK call context

        Returns:
            True if a service-specific extension exists, False otherwise
        """
        return call_context.service in self._extensions

    def get_instrumentation_name(self, extension: _AwsSdkExtension) -> str:
        """
        Get the instrumentation name for an extension.

        Service-specific extensions get a namespaced name (e.g., 'module.s3'),
        while the default extension uses just the module name.

        Args:
            extension: The AWS SDK extension

        Returns:
            The instrumentation name string
        """
        if self.has_extension(extension._call_context):
            return f"{self._package_name}.{extension._call_context.service}"
        return self._package_name

    def get_tracer(self, extension: _AwsSdkExtension) -> Tracer:
        """
        Get or create a tracer for the given extension.

        Tracers are cached per instrumentation name for reuse.

        Args:
            extension: The AWS SDK extension

        Returns:
            A configured Tracer instance
        """
        instrumentation_name: str = self.get_instrumentation_name(extension)
        if instrumentation_name in self._tracers:
            return self._tracers[instrumentation_name]

        schema_version: str = extension.tracer_schema_version()
        tracer: Tracer = get_tracer(
            instrumentation_name,
            __version__,
            self._tracer_provider,
            schema_url=f"https://opentelemetry.io/schemas/{schema_version}",
        )
        self._tracers[instrumentation_name] = tracer
        return tracer

    def get_logger(self, extension: _AwsSdkExtension):
        """
        Get or create a logger for the given extension.

        Loggers are cached per instrumentation name for reuse.

        Args:
            extension: The AWS SDK extension

        Returns:
            A configured Logger instance
        """
        instrumentation_name: str = self.get_instrumentation_name(extension)
        if instrumentation_name in self._loggers:
            return self._loggers[instrumentation_name]

        schema_version: str = extension.event_logger_schema_version()
        logger: Logger = get_logger(
            instrumentation_name,
            schema_url=f"https://opentelemetry.io/schemas/{schema_version}",
            logger_provider=self._logger_provider,
        )
        self._loggers[instrumentation_name] = logger
        return logger

    def get_meter(self, extension: _AwsSdkExtension) -> Meter:
        """
        Get or create a meter for the given extension.

        Meters are cached per instrumentation name for reuse.

        Args:
            extension: The AWS SDK extension

        Returns:
            A configured Meter instance
        """
        instrumentation_name: str = self.get_instrumentation_name(extension)
        if instrumentation_name in self._meters:
            return self._meters[instrumentation_name]

        schema_version: str = extension.meter_schema_version()
        meter = get_meter(
            instrumentation_name,
            "",
            schema_url=f"https://opentelemetry.io/schemas/{schema_version}",
            meter_provider=self._meter_provider,
        )
        self._meters[instrumentation_name] = meter
        return meter

    def get_metrics(
        self, extension: _AwsSdkExtension
    ) -> dict[str, Instrument]:
        """
        Get or create metrics for the given extension.

        Metrics are lazily initialized by calling the extension's setup_metrics method.

        Args:
            extension: The AWS SDK extension

        Returns:
            A dictionary mapping metric names to Instrument instances
        """
        instrumentation_name: str = self.get_instrumentation_name(extension)
        if instrumentation_name in self._metrics:
            return self._metrics[instrumentation_name]

        meter: Meter = self.get_meter(extension)
        metrics: dict[str, Instrument] = {}
        _safe_invoke(extension.setup_metrics, meter, metrics)
        self._metrics[instrumentation_name] = metrics
        return metrics
