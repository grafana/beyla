# Copyright 2020, OpenTelemetry Authors
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
The opentelemetry-instrumentation-aws-lambda package provides an Instrumentor
to traces calls within a Python AWS Lambda function.

Usage
-----

.. code:: python

    # Copy this snippet into an AWS Lambda function

    import boto3
    from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
    from opentelemetry.instrumentation.aws_lambda import AwsLambdaInstrumentor

    # Enable instrumentation
    BotocoreInstrumentor().instrument()

    # Lambda function
    def lambda_handler(event, context):
        s3 = boto3.resource('s3')
        for bucket in s3.buckets.all():
            print(bucket.name)

        return "200 OK"

    AwsLambdaInstrumentor().instrument()

API
---

The `instrument` method accepts the following keyword args:

tracer_provider (TracerProvider) - an optional tracer provider
meter_provider (MeterProvider) - an optional meter provider
event_context_extractor (Callable) - a function that returns an OTel Trace
Context given the Lambda Event the AWS Lambda was invoked with
this function signature is: def event_context_extractor(lambda_event: Any) -> Context
for example:

.. code:: python

    from opentelemetry.instrumentation.aws_lambda import AwsLambdaInstrumentor
    from opentelemetry.propagate import get_global_textmap

    def custom_event_context_extractor(lambda_event):
        # If the `TraceContextTextMapPropagator` is the global propagator, we
        # can use it to parse out the context from the HTTP Headers.
        return get_global_textmap().extract(lambda_event["foo"]["headers"])

    AwsLambdaInstrumentor().instrument(
        event_context_extractor=custom_event_context_extractor
    )

---
"""

from __future__ import annotations

import logging
import os
import time
from importlib import import_module
from typing import TYPE_CHECKING, Any, Callable, Collection
from urllib.parse import urlencode

from wrapt import wrap_function_wrapper

from opentelemetry import context as context_api
from opentelemetry.context.context import Context
from opentelemetry.instrumentation.aws_lambda.package import _instruments
from opentelemetry.instrumentation.aws_lambda.version import __version__
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import unwrap
from opentelemetry.metrics import MeterProvider, get_meter_provider
from opentelemetry.propagate import get_global_textmap
from opentelemetry.semconv._incubating.attributes.cloud_attributes import (
    CLOUD_ACCOUNT_ID,
    CLOUD_RESOURCE_ID,
)
from opentelemetry.semconv._incubating.attributes.faas_attributes import (
    FAAS_INVOCATION_ID,
    FAAS_TRIGGER,
)
from opentelemetry.semconv._incubating.attributes.http_attributes import (
    HTTP_METHOD,
    HTTP_ROUTE,
    HTTP_SCHEME,
    HTTP_STATUS_CODE,
    HTTP_TARGET,
    HTTP_USER_AGENT,
)
from opentelemetry.semconv._incubating.attributes.net_attributes import (
    NET_HOST_NAME,
)
from opentelemetry.trace import (
    Span,
    SpanKind,
    TracerProvider,
    get_tracer,
    get_tracer_provider,
)
from opentelemetry.trace.status import Status, StatusCode

logger = logging.getLogger(__name__)

_HANDLER = "_HANDLER"
_X_AMZN_TRACE_ID = "_X_AMZN_TRACE_ID"
ORIG_HANDLER = "ORIG_HANDLER"
OTEL_INSTRUMENTATION_AWS_LAMBDA_FLUSH_TIMEOUT = (
    "OTEL_INSTRUMENTATION_AWS_LAMBDA_FLUSH_TIMEOUT"
)

if TYPE_CHECKING:
    import typing

    class LambdaContext(typing.Protocol):
        """Type definition for AWS Lambda context object.

        This Protocol defines the interface for the context object passed to Lambda
        function handlers, providing information about the invocation, function, and
        execution environment.

         See Also:
            AWS Lambda Context Object documentation:
            https://docs.aws.amazon.com/lambda/latest/dg/python-context.html
        """

        function_name: str
        function_version: str
        invoked_function_arn: str
        memory_limit_in_mb: int
        aws_request_id: str
        log_group_name: str
        log_stream_name: str


def _default_event_context_extractor(lambda_event: Any) -> Context:
    """Default way of extracting the context from the Lambda Event.

    Assumes the Lambda Event is a map with the headers under the 'headers' key.
    This is the mapping to use when the Lambda is invoked by an API Gateway
    REST API where API Gateway is acting as a pure proxy for the request.
    Protects headers from being something other than dictionary, as this
    is what downstream propagators expect.

    See more:
    https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format

    Args:
        lambda_event: user-defined, so it could be anything, but this
            method counts on it being a map with a 'headers' key
    Returns:
        A Context with configuration found in the event.
    """
    headers = None
    try:
        headers = lambda_event["headers"]
    except (TypeError, KeyError):
        logger.debug(
            "Extracting context from Lambda Event failed: either enable X-Ray active tracing or configure API Gateway to trigger this Lambda function as a pure proxy. Otherwise, generated spans will have an invalid (empty) parent context."
        )
    if not isinstance(headers, dict):
        headers = {}
    return get_global_textmap().extract(headers)


def _determine_parent_context(
    lambda_event: Any,
    event_context_extractor: Callable[[Any], Context],
) -> Context:
    """Determine the parent context for the current Lambda invocation.

    See more:
    https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/instrumentation/aws-lambda.md#determining-the-parent-of-a-span

    Args:
        lambda_event: user-defined, so it could be anything, but this
            method counts it being a map with a 'headers' key
        event_context_extractor: a method which takes the Lambda
            Event as input and extracts an OTel Context from it. By default,
            the context is extracted from the HTTP headers of an API Gateway
            request.
    Returns:
        A Context with configuration found in the carrier.
    """

    if event_context_extractor is None:
        return _default_event_context_extractor(lambda_event)

    return event_context_extractor(lambda_event)


def _set_api_gateway_v1_proxy_attributes(
    lambda_event: Any, span: Span
) -> Span:
    """Sets HTTP attributes for REST APIs and v1 HTTP APIs

    More info:
    https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
    """
    span.set_attribute(HTTP_METHOD, lambda_event.get("httpMethod"))

    if lambda_event.get("headers"):
        if "User-Agent" in lambda_event["headers"]:
            span.set_attribute(
                HTTP_USER_AGENT,
                lambda_event["headers"]["User-Agent"],
            )
        if "X-Forwarded-Proto" in lambda_event["headers"]:
            span.set_attribute(
                HTTP_SCHEME,
                lambda_event["headers"]["X-Forwarded-Proto"],
            )
        if "Host" in lambda_event["headers"]:
            span.set_attribute(
                NET_HOST_NAME,
                lambda_event["headers"]["Host"],
            )
    if "resource" in lambda_event:
        span.set_attribute(HTTP_ROUTE, lambda_event["resource"])

        if lambda_event.get("queryStringParameters"):
            span.set_attribute(
                HTTP_TARGET,
                f"{lambda_event['resource']}?{urlencode(lambda_event['queryStringParameters'])}",
            )
        else:
            span.set_attribute(HTTP_TARGET, lambda_event["resource"])

    return span


def _set_api_gateway_v2_proxy_attributes(
    lambda_event: Any, span: Span
) -> Span:
    """Sets HTTP attributes for v2 HTTP APIs

    More info:
    https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
    """
    if "domainName" in lambda_event["requestContext"]:
        span.set_attribute(
            NET_HOST_NAME,
            lambda_event["requestContext"]["domainName"],
        )

    if lambda_event["requestContext"].get("http"):
        if "method" in lambda_event["requestContext"]["http"]:
            span.set_attribute(
                HTTP_METHOD,
                lambda_event["requestContext"]["http"]["method"],
            )
        if "userAgent" in lambda_event["requestContext"]["http"]:
            span.set_attribute(
                HTTP_USER_AGENT,
                lambda_event["requestContext"]["http"]["userAgent"],
            )
        if "path" in lambda_event["requestContext"]["http"]:
            span.set_attribute(
                HTTP_ROUTE,
                lambda_event["requestContext"]["http"]["path"],
            )
            if lambda_event.get("rawQueryString"):
                span.set_attribute(
                    HTTP_TARGET,
                    f"{lambda_event['requestContext']['http']['path']}?{lambda_event['rawQueryString']}",
                )
            else:
                span.set_attribute(
                    HTTP_TARGET,
                    lambda_event["requestContext"]["http"]["path"],
                )

    return span


def _get_lambda_context_attributes(
    lambda_context: LambdaContext,
) -> dict[str, str]:
    """Extracts OpenTelemetry span attributes from AWS Lambda context.

    Extract FaaS specific attributes from the AWS Lambda context
    according to OpenTelemetry semantic conventions for FaaS & AWS Lambda.

    Args:
        lambda_context: The AWS Lambda context object.

    Returns:
        A dictionary mapping of OpenTelemetry attribute names to their values.
    """
    function_arn_parts: list[str] = lambda_context.invoked_function_arn.split(
        ":"
    )
    # NOTE: `cloud.account.id` can be parsed from the ARN as the fifth item when splitting on `:`
    #
    # See more:
    # https://github.com/open-telemetry/semantic-conventions/blob/main/docs/faas/aws-lambda.md#all-triggers
    aws_account_id: str = function_arn_parts[4]
    # NOTE: The unmodified function ARN may contain an alias extension e.g.
    # `arn:aws:lambda:region:account:function:name:alias`. We can ensure
    # the alias extension is not included in the `cloud.resource_id` by keeping
    # only the first 7 parts of the original ARN.
    #
    # See more:
    # https://docs.aws.amazon.com/lambda/latest/dg/python-context.html
    formatted_function_arn: str = ":".join(function_arn_parts[:7])

    # NOTE: The specs mention an exception here, allowing the
    # `SpanAttributes.CLOUD_RESOURCE_ID` attribute to be set as a span
    # attribute instead of a resource attribute.
    #
    # See more:
    # https://github.com/open-telemetry/semantic-conventions/blob/main/docs/faas/aws-lambda.md#resource-detector
    return {
        CLOUD_ACCOUNT_ID: aws_account_id,
        CLOUD_RESOURCE_ID: formatted_function_arn,
        FAAS_INVOCATION_ID: lambda_context.aws_request_id,
    }


# pylint: disable=too-many-statements
def _instrument(
    wrapped_module_name,
    wrapped_function_name,
    flush_timeout,
    event_context_extractor: Callable[[Any], Context],
    tracer_provider: TracerProvider = None,
    meter_provider: MeterProvider = None,
):
    # pylint: disable=too-many-locals
    # pylint: disable=too-many-statements
    def _instrumented_lambda_handler_call(  # noqa pylint: disable=too-many-branches
        call_wrapped, instance, args, kwargs
    ):
        lambda_event: Any = args[0]
        lambda_context: LambdaContext = args[1]

        parent_context = _determine_parent_context(
            lambda_event,
            event_context_extractor,
        )

        tracer = get_tracer(
            __name__,
            __version__,
            tracer_provider,
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )

        token = context_api.attach(parent_context)
        try:
            with tracer.start_as_current_span(
                name=lambda_context.function_name,
                kind=SpanKind.SERVER,
                attributes=_get_lambda_context_attributes(lambda_context),
            ) as span:
                exception = None
                result = None
                try:
                    result = call_wrapped(*args, **kwargs)
                except Exception as exc:  # pylint: disable=W0703
                    exception = exc
                    span.set_status(Status(StatusCode.ERROR))
                    span.record_exception(exception)

                # If the request came from an API Gateway, extract http attributes from the event
                # https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/instrumentation/aws-lambda.md#api-gateway
                # https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/http.md#http-server-semantic-conventions
                if isinstance(lambda_event, dict) and lambda_event.get(
                    "requestContext"
                ):
                    span.set_attribute(FAAS_TRIGGER, "http")

                    if lambda_event.get("version") == "2.0":
                        _set_api_gateway_v2_proxy_attributes(
                            lambda_event, span
                        )
                    else:
                        _set_api_gateway_v1_proxy_attributes(
                            lambda_event, span
                        )

                    if isinstance(result, dict) and result.get("statusCode"):
                        span.set_attribute(
                            HTTP_STATUS_CODE,
                            result.get("statusCode"),
                        )
        finally:
            if token:
                context_api.detach(token)

        now = time.time()
        _tracer_provider = tracer_provider or get_tracer_provider()
        if hasattr(_tracer_provider, "force_flush"):
            try:
                # NOTE: `force_flush` before function quit in case of Lambda freeze.
                _tracer_provider.force_flush(flush_timeout)
            except Exception:  # pylint: disable=broad-except
                logger.exception("TracerProvider failed to flush traces")
        else:
            logger.warning(
                "TracerProvider was missing `force_flush` method. This is necessary in case of a Lambda freeze and would exist in the OTel SDK implementation."
            )

        _meter_provider = meter_provider or get_meter_provider()
        if hasattr(_meter_provider, "force_flush"):
            rem = flush_timeout - (time.time() - now) * 1000
            if rem > 0:
                try:
                    # NOTE: `force_flush` before function quit in case of Lambda freeze.
                    _meter_provider.force_flush(rem)
                except Exception:  # pylint: disable=broad-except
                    logger.exception("MeterProvider failed to flush metrics")
        else:
            logger.warning(
                "MeterProvider was missing `force_flush` method. This is necessary in case of a Lambda freeze and would exist in the OTel SDK implementation."
            )

        if exception is not None:
            raise exception.with_traceback(exception.__traceback__)

        return result

    wrap_function_wrapper(
        wrapped_module_name,
        wrapped_function_name,
        _instrumented_lambda_handler_call,
    )


class AwsLambdaInstrumentor(BaseInstrumentor):
    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs):
        """Instruments Lambda Handlers on AWS Lambda.

        See more:
        https://github.com/open-telemetry/semantic-conventions/blob/main/docs/faas/aws-lambda.md

        Args:
            **kwargs: Optional arguments
                ``tracer_provider``: a TracerProvider, defaults to global
                ``meter_provider``: a MeterProvider, defaults to global
                ``event_context_extractor``: a method which takes the Lambda
                    Event as input and extracts an OTel Context from it. By default,
                    the context is extracted from the HTTP headers of an API Gateway
                    request.
        """

        # Don't try if we are not running on AWS Lambda
        if "AWS_LAMBDA_FUNCTION_NAME" not in os.environ:
            return

        lambda_handler = os.environ.get(ORIG_HANDLER, os.environ.get(_HANDLER))
        if not lambda_handler:
            logger.warning(
                (
                    "Could not find the ORIG_HANDLER or _HANDLER in the environment variables. ",
                    "This instrumentation requires the OpenTelemetry Lambda extension installed.",
                )
            )
            return
        # pylint: disable=attribute-defined-outside-init
        # Convert slash-delimited paths to dot-delimited for valid Python imports
        lambda_handler = lambda_handler.replace("/", ".")
        (
            self._wrapped_module_name,
            self._wrapped_function_name,
        ) = lambda_handler.rsplit(".", 1)

        flush_timeout_env = os.environ.get(
            OTEL_INSTRUMENTATION_AWS_LAMBDA_FLUSH_TIMEOUT, None
        )
        flush_timeout = 30000
        try:
            if flush_timeout_env is not None:
                flush_timeout = int(flush_timeout_env)
        except ValueError:
            logger.warning(
                "Could not convert OTEL_INSTRUMENTATION_AWS_LAMBDA_FLUSH_TIMEOUT value %s to int",
                flush_timeout_env,
            )

        _instrument(
            self._wrapped_module_name,
            self._wrapped_function_name,
            flush_timeout,
            event_context_extractor=kwargs.get(
                "event_context_extractor", _default_event_context_extractor
            ),
            tracer_provider=kwargs.get("tracer_provider"),
            meter_provider=kwargs.get("meter_provider"),
        )

    def _uninstrument(self, **kwargs):
        unwrap(
            import_module(self._wrapped_module_name),
            self._wrapped_function_name,
        )
