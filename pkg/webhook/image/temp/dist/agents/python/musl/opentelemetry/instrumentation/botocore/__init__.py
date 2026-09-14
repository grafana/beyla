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

"""
Instrument `botocore`_ and `aiobotocore`_ to trace service requests.

There are two options for instrumenting code. The first option is to use the
``opentelemetry-instrument`` executable which will automatically
instrument your botocore or aiobotocore client. The second is to programmatically enable
instrumentation via the following code:

.. _botocore: https://pypi.org/project/botocore/
.. _aiobotocore: https://pypi.org/project/aiobotocore/

Usage
-----

.. code:: python

    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    import botocore.session


    # Instrument botocore
    BotocoreInstrumentor().instrument()

    # This will create a span with botocore-specific attributes
    session = botocore.session.get_session()
    session.set_credentials(
        access_key="access-key", secret_key="secret-key"
    )
    ec2 = session.create_client("ec2", region_name="us-west-2")
    ec2.describe_instances()

Async Usage
-----------

.. code:: python

    from opentelemetry.instrumentation.botocore import AiobotocoreInstrumentor
    import aiobotocore.session
    import asyncio


    async def main():
        # Instrument Aiobotocore
        AiobotocoreInstrumentor().instrument()

        # This will create a span with aiobotocore-specific attributes
        session = aiobotocore.session.get_session()
        async with session.create_client("ec2") as client:
            await client.describe_instances()

    asyncio.run(main())

Thread Context Propagation
--------------------------

boto3's S3 ``upload_file`` and ``download_file`` methods use background threads
for multipart transfers. To ensure trace context is propagated to these threads,
also enable the threading instrumentation:

.. code:: python

    from opentelemetry.instrumentation.threading import ThreadingInstrumentor
    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor

    ThreadingInstrumentor().instrument()
    BotocoreInstrumentor().instrument()

When using auto-instrumentation (``opentelemetry-instrument``), both instrumentors
are enabled automatically if their packages are installed.

API
---

The `instrument` method (for both ``BotocoreInstrumentor`` and ``AiobotocoreInstrumentor``) accepts the following keyword args:

* tracer_provider (``TracerProvider``) - an optional tracer provider
* request_hook (``Callable[[Span, str, str, dict], None]``) - a function with extra user-defined logic to be performed before performing the request
* response_hook (``Callable[[Span, str, str, dict], None]``) - a function with extra user-defined logic to be performed after performing the request

for example:

.. code:: python

    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    import botocore.session

    def request_hook(span, service_name, operation_name, api_params):
        # request hook logic
        pass

    def response_hook(span, service_name, operation_name, result):
        # response hook logic
        pass

    # Instrument botocore with hooks
    BotocoreInstrumentor().instrument(request_hook=request_hook, response_hook=response_hook)

    # This will create a span with botocore-specific attributes, including custom attributes added from the hooks
    session = botocore.session.get_session()
    session.set_credentials(
        access_key="access-key", secret_key="secret-key"
    )
    ec2 = session.create_client("ec2", region_name="us-west-2")
    ec2.describe_instances()
"""

import logging
from typing import Any, Collection, Dict, Optional, Tuple

from botocore.client import BaseClient
from botocore.endpoint import Endpoint
from botocore.exceptions import ClientError
from wrapt import wrap_function_wrapper

from opentelemetry.instrumentation.botocore.extensions import (
    _AIOBOTOCORE_EXTENSIONS,
    _BOTOCORE_EXTENSIONS,
)
from opentelemetry.instrumentation.botocore.extensions.registry import (
    ExtensionRegistry,
)
from opentelemetry.instrumentation.botocore.extensions.types import (
    _AwsSdkCallContext,
    _BotocoreInstrumentorContext,
)
from opentelemetry.instrumentation.botocore.package import (
    _instruments_aiobotocore,
    _instruments_botocore,
)
from opentelemetry.instrumentation.botocore.utils import (
    _safe_invoke,
    get_server_attributes,
)
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import (
    is_instrumentation_enabled,
    suppress_http_instrumentation,
    unwrap,
)
from opentelemetry.propagators.aws.aws_xray_propagator import (
    TRACE_HEADER_KEY,
    AwsXRayPropagator,
)
from opentelemetry.semconv._incubating.attributes.cloud_attributes import (
    CLOUD_REGION,
)
from opentelemetry.semconv._incubating.attributes.http_attributes import (
    HTTP_STATUS_CODE,
)
from opentelemetry.semconv._incubating.attributes.rpc_attributes import (
    RPC_METHOD,
    RPC_SERVICE,
    RPC_SYSTEM,
)
from opentelemetry.trace.span import Span

logger = logging.getLogger(__name__)


class BotocoreInstrumentor(BaseInstrumentor):
    """An instrumentor for Botocore.

    See `BaseInstrumentor`
    """

    def __init__(self):
        super().__init__()
        if not hasattr(self, "request_hook"):
            self.request_hook = None
        if not hasattr(self, "response_hook"):
            self.response_hook = None
        if not hasattr(self, "extension_registry"):
            self.extension_registry = None
        if not hasattr(self, "propagator"):
            self.propagator = AwsXRayPropagator()

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments_botocore

    def _instrument(self, **kwargs):
        # pylint: disable=attribute-defined-outside-init
        self.request_hook = kwargs.get("request_hook")
        self.response_hook = kwargs.get("response_hook")

        propagator = kwargs.get("propagator")
        if propagator is not None:
            self.propagator = propagator

        self.extension_registry = ExtensionRegistry(
            __name__,
            _BOTOCORE_EXTENSIONS,
            kwargs.get("tracer_provider"),
            kwargs.get("logger_provider"),
            kwargs.get("meter_provider"),
        )

        wrap_function_wrapper(
            "botocore.client",
            "BaseClient._make_api_call",
            self._patched_api_call,
        )

        wrap_function_wrapper(
            "botocore.endpoint",
            "Endpoint.prepare_request",
            self._patched_endpoint_prepare_request,
        )

    def _uninstrument(self, **kwargs):
        unwrap(BaseClient, "_make_api_call")
        unwrap(Endpoint, "prepare_request")

    # pylint: disable=unused-argument
    def _patched_endpoint_prepare_request(
        self, wrapped, instance, args, kwargs
    ):
        request = args[0]
        headers = request.headers

        # There may be situations where both Botocore and Aiobotocore are
        # instrumented at the same time. To avoid double-injection of headers,
        # we add a check to see if the header is already present. If it is,
        # we skip injection.
        if TRACE_HEADER_KEY in headers:
            return wrapped(*args, **kwargs)

        # Only the x-ray header is propagated by AWS services. Using any
        # other propagator will lose the trace context.
        self.propagator.inject(headers)

        return wrapped(*args, **kwargs)

    # pylint: disable=too-many-branches
    def _patched_api_call(self, original_func, instance, args, kwargs):
        if not is_instrumentation_enabled():
            return original_func(*args, **kwargs)

        call_context = _determine_call_context(instance, args)
        if call_context is None:
            return original_func(*args, **kwargs)

        extension = self.extension_registry.get_extension(call_context)
        if not extension.should_trace_service_call():
            return original_func(*args, **kwargs)

        attributes = {
            RPC_SYSTEM: "aws-api",
            RPC_SERVICE: call_context.service_id,
            RPC_METHOD: call_context.operation,
            CLOUD_REGION: call_context.region,
            **get_server_attributes(call_context.endpoint_url),
        }

        _safe_invoke(extension.extract_attributes, attributes)
        end_span_on_exit = extension.should_end_span_on_exit()

        tracer = self.extension_registry.get_tracer(extension)
        metrics = self.extension_registry.get_metrics(extension)
        instrumentor_ctx = _BotocoreInstrumentorContext(
            logger=self.extension_registry.get_logger(extension),
            metrics=metrics,
        )
        with tracer.start_as_current_span(
            call_context.span_name,
            kind=call_context.span_kind,
            attributes=attributes,
            # tracing streaming services require to close the span manually
            # at a later time after the stream has been consumed
            end_on_exit=end_span_on_exit,
        ) as span:
            _safe_invoke(extension.before_service_call, span, instrumentor_ctx)
            self._call_request_hook(span, call_context)

            try:
                with suppress_http_instrumentation():
                    result = None
                    try:
                        result = original_func(*args, **kwargs)
                    except ClientError as error:
                        result = getattr(error, "response", None)
                        _apply_response_attributes(span, result)
                        _safe_invoke(
                            extension.on_error, span, error, instrumentor_ctx
                        )
                        raise
                    _apply_response_attributes(span, result)
                    _safe_invoke(
                        extension.on_success, span, result, instrumentor_ctx
                    )
            finally:
                _safe_invoke(extension.after_service_call, instrumentor_ctx)
                self._call_response_hook(span, call_context, result)

            return result

    def _call_request_hook(self, span: Span, call_context: _AwsSdkCallContext):
        if not callable(self.request_hook):
            return
        self.request_hook(
            span,
            call_context.service,
            call_context.operation,
            call_context.params,
        )

    def _call_response_hook(
        self, span: Span, call_context: _AwsSdkCallContext, result
    ):
        if not callable(self.response_hook):
            return
        self.response_hook(
            span, call_context.service, call_context.operation, result
        )


class AiobotocoreInstrumentor(BaseInstrumentor):
    """An instrumentor for Aiobotocore.

    See `BaseInstrumentor`
    """

    def __init__(self):
        super().__init__()
        if not hasattr(self, "request_hook"):
            self.request_hook = None
        if not hasattr(self, "response_hook"):
            self.response_hook = None
        if not hasattr(self, "extension_registry"):
            self.extension_registry = None
        if not hasattr(self, "propagator"):
            self.propagator = AwsXRayPropagator()

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments_aiobotocore

    def _instrument(self, **kwargs):
        # Verify that aiobotocore is present
        # pylint: disable-next=import-outside-toplevel, unused-import
        import aiobotocore.client  # noqa: PLC0415, F401

        # pylint: disable=attribute-defined-outside-init
        self.request_hook = kwargs.get("request_hook")
        self.response_hook = kwargs.get("response_hook")

        propagator = kwargs.get("propagator")
        if propagator is not None:
            self.propagator = propagator

        self.extension_registry = ExtensionRegistry(
            __name__,
            _AIOBOTOCORE_EXTENSIONS,
            kwargs.get("tracer_provider"),
            kwargs.get("logger_provider"),
            kwargs.get("meter_provider"),
        )

        wrap_function_wrapper(
            "aiobotocore.client",
            "AioBaseClient._make_api_call",
            self._patched_api_call,
        )

        wrap_function_wrapper(
            "botocore.endpoint",
            "Endpoint.prepare_request",
            self._patched_endpoint_prepare_request,
        )

    def _uninstrument(self, **kwargs):
        unwrap("aiobotocore.client.AioBaseClient", "_make_api_call")
        unwrap(Endpoint, "prepare_request")

    # pylint: disable=unused-argument
    def _patched_endpoint_prepare_request(
        self, wrapped, instance, args, kwargs
    ):
        request = args[0]
        headers = request.headers

        # There may be situations where both Botocore and Aiobotocore are
        # instrumented at the same time. To avoid double-injection of headers,
        # we add a check to see if the header is already present. If it is,
        # we skip injection.
        if TRACE_HEADER_KEY in headers:
            return wrapped(*args, **kwargs)

        # Only the x-ray header is propagated by AWS services. Using any
        # other propagator will lose the trace context.
        self.propagator.inject(headers)

        return wrapped(*args, **kwargs)

    # pylint: disable=too-many-branches
    async def _patched_api_call(self, original_func, instance, args, kwargs):
        if not is_instrumentation_enabled():
            return await original_func(*args, **kwargs)

        call_context = _determine_call_context(instance, args)
        if call_context is None:
            return await original_func(*args, **kwargs)

        extension = self.extension_registry.get_extension(call_context)
        if not extension.should_trace_service_call():
            return await original_func(*args, **kwargs)

        attributes = {
            RPC_SYSTEM: "aws-api",
            RPC_SERVICE: call_context.service_id,
            RPC_METHOD: call_context.operation,
            CLOUD_REGION: call_context.region,
            **get_server_attributes(call_context.endpoint_url),
        }

        _safe_invoke(extension.extract_attributes, attributes)
        end_span_on_exit = extension.should_end_span_on_exit()

        tracer = self.extension_registry.get_tracer(extension)
        metrics = self.extension_registry.get_metrics(extension)
        instrumentor_ctx = _BotocoreInstrumentorContext(
            logger=self.extension_registry.get_logger(extension),
            metrics=metrics,
        )
        with tracer.start_as_current_span(
            call_context.span_name,
            kind=call_context.span_kind,
            attributes=attributes,
            # tracing streaming services require to close the span manually
            # at a later time after the stream has been consumed
            end_on_exit=end_span_on_exit,
        ) as span:
            _safe_invoke(extension.before_service_call, span, instrumentor_ctx)
            self._call_request_hook(span, call_context)

            try:
                with suppress_http_instrumentation():
                    result = None
                    try:
                        result = await original_func(*args, **kwargs)
                    except ClientError as error:
                        result = getattr(error, "response", None)
                        _apply_response_attributes(span, result)
                        _safe_invoke(
                            extension.on_error, span, error, instrumentor_ctx
                        )
                        raise
                    _apply_response_attributes(span, result)
                    _safe_invoke(
                        extension.on_success, span, result, instrumentor_ctx
                    )
            finally:
                _safe_invoke(extension.after_service_call, instrumentor_ctx)
                self._call_response_hook(span, call_context, result)

            return result

    def _call_request_hook(self, span: Span, call_context: _AwsSdkCallContext):
        if not callable(self.request_hook):
            return
        self.request_hook(
            span,
            call_context.service,
            call_context.operation,
            call_context.params,
        )

    def _call_response_hook(
        self, span: Span, call_context: _AwsSdkCallContext, result
    ):
        if not callable(self.response_hook):
            return
        self.response_hook(
            span, call_context.service, call_context.operation, result
        )


def _apply_response_attributes(span: Span, result):
    if result is None or not span.is_recording():
        return

    metadata = result.get("ResponseMetadata")
    if metadata is None:
        return

    request_id = metadata.get("RequestId")
    if request_id is None:
        headers = metadata.get("HTTPHeaders")
        if headers is not None:
            request_id = (
                headers.get("x-amzn-RequestId")
                or headers.get("x-amz-request-id")
                or headers.get("x-amz-id-2")
            )
    if request_id:
        # TODO: update when semantic conventions exist
        span.set_attribute("aws.request_id", request_id)

    retry_attempts = metadata.get("RetryAttempts")
    if retry_attempts is not None:
        # TODO: update when semantic conventions exists
        span.set_attribute("retry_attempts", retry_attempts)

    status_code = metadata.get("HTTPStatusCode")
    if status_code is not None:
        span.set_attribute(HTTP_STATUS_CODE, status_code)


def _determine_call_context(
    client: BaseClient, args: Tuple[str, Dict[str, Any]]
) -> Optional[_AwsSdkCallContext]:
    try:
        call_context = _AwsSdkCallContext(client, args)

        logger.debug(
            "AWS SDK invocation: %s %s",
            call_context.service,
            call_context.operation,
        )

        return call_context
    except Exception as ex:  # pylint:disable=broad-except
        # this shouldn't happen actually unless internals of botocore changed and
        # extracting essential attributes ('service' and 'operation') failed.
        logger.error("Error when initializing call context", exc_info=ex)
        return None
