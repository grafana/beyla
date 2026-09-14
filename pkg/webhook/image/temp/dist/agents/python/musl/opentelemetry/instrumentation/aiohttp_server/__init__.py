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
The opentelemetry-instrumentation-aiohttp-server package allows tracing HTTP
requests made by the aiohttp server library.

Usage
-----

.. code:: python

    from aiohttp import web
    from opentelemetry.instrumentation.aiohttp_server import (
        AioHttpServerInstrumentor
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

    # Optional: configure non-default TracerProvider, resource, sampler
    resource = Resource(attributes={"service.name": "my-aiohttp-service"})
    sampler = ParentBased(root=TraceIdRatioBased(rate=0.25))  # sample 25% of traces
    AioHttpServerInstrumentor().instrument(tracer_provider=TracerProvider(resource=resource, sampler=sampler))

    async def hello(request):
        return web.Response(text="Hello, world")

    app = web.Application()
    app.add_routes([web.get('/', hello)])

    web.run_app(app)


Configuration
-------------

Exclude lists
*************
To exclude certain URLs from tracking, set the environment variable ``OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS``
(or ``OTEL_PYTHON_EXCLUDED_URLS`` to cover all instrumentations) to a string of comma delimited regexes that match the
URLs.

For example,

::

    export OTEL_PYTHON_AIOHTTP_SERVER_EXCLUDED_URLS="client/.*/info,healthcheck"

will exclude requests such as ``https://site/client/123/info`` and ``https://site/xyz/healthcheck``.

Capture HTTP request and response headers
*****************************************
You can configure the agent to capture specified HTTP headers as span attributes, according to the
`semantic conventions <https://github.com/open-telemetry/semantic-conventions/blob/main/docs/http/http-spans.md#http-server-span>`_.

Request headers
***************
To capture HTTP request headers as span attributes, set the environment variable
``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST`` to a comma delimited list of HTTP header names.

For example,
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST="content-type,custom_request_header"

will extract ``content-type`` and ``custom_request_header`` from the request headers and add them as span attributes.

Request header names in aiohttp are case-insensitive. So, giving the header name as ``CUStom-Header`` in the environment
variable will capture the header named ``custom-header``.

Regular expressions may also be used to match multiple headers that correspond to the given pattern.  For example:
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST="Accept.*,X-.*"

Would match all request headers that start with ``Accept`` and ``X-``.

To capture all request headers, set ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST`` to ``".*"``.
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST=".*"

The name of the added span attribute will follow the format ``http.request.header.<header_name>`` where ``<header_name>``
is the normalized HTTP header name (lowercase, with ``-`` replaced by ``_``). The value of the attribute will be a
list containing the header values.

For example:
``http.request.header.custom_request_header = ["<value1>, <value2>"]``

Response headers
****************
To capture HTTP response headers as span attributes, set the environment variable
``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE`` to a comma delimited list of HTTP header names.

For example,
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE="content-type,custom_response_header"

will extract ``content-type`` and ``custom_response_header`` from the response headers and add them as span attributes.

Response header names in aiohttp are case-insensitive. So, giving the header name as ``CUStom-Header`` in the environment
variable will capture the header named ``custom-header``.

Regular expressions may also be used to match multiple headers that correspond to the given pattern.  For example:
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE="Content.*,X-.*"

Would match all response headers that start with ``Content`` and ``X-``.

To capture all response headers, set ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE`` to ``".*"``.
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE=".*"

The name of the added span attribute will follow the format ``http.response.header.<header_name>`` where ``<header_name>``
is the normalized HTTP header name (lowercase, with ``-`` replaced by ``_``). The value of the attribute will be a
list containing the header values.

For example:
``http.response.header.custom_response_header = ["<value1>, <value2>"]``

Sanitizing headers
******************
In order to prevent storing sensitive data such as personally identifiable information (PII), session keys, passwords,
etc, set the environment variable ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS``
to a comma delimited list of HTTP header names to be sanitized.  Regexes may be used, and all header names will be
matched in a case-insensitive manner.

For example,
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS=".*session.*,set-cookie"

will replace the value of headers such as ``session-id`` and ``set-cookie`` with ``[REDACTED]`` in the span.

Note:
    The environment variable names used to capture HTTP headers are still experimental, and thus are subject to change.

API
---
"""

from __future__ import annotations

from timeit import default_timer

from aiohttp import web
from multidict import CIMultiDictProxy

from opentelemetry import metrics, trace
from opentelemetry.instrumentation._semconv import (
    HTTP_DURATION_HISTOGRAM_BUCKETS_NEW,
    _filter_semconv_active_request_count_attr,
    _filter_semconv_duration_attrs,
    _get_schema_url,
    _OpenTelemetrySemanticConventionStability,
    _OpenTelemetryStabilitySignalType,
    _report_new,
    _report_old,
    _server_active_requests_count_attrs_new,
    _server_active_requests_count_attrs_old,
    _server_duration_attrs_new,
    _server_duration_attrs_old,
    _set_http_flavor_version,
    _set_http_method,
    _set_http_net_host,
    _set_http_net_host_port,
    _set_http_scheme,
    _set_http_target,
    _set_http_user_agent,
    _set_status,
    _StabilityMode,
)
from opentelemetry.instrumentation.aiohttp_server.package import _instruments
from opentelemetry.instrumentation.aiohttp_server.version import __version__
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import (
    is_http_instrumentation_enabled,
)
from opentelemetry.propagate import extract
from opentelemetry.propagators.textmap import Getter
from opentelemetry.semconv._incubating.attributes.http_attributes import (
    HTTP_HOST,
    HTTP_ROUTE,
    HTTP_SERVER_NAME,
    HTTP_URL,
)
from opentelemetry.semconv.metrics import MetricInstruments
from opentelemetry.semconv.metrics.http_metrics import (
    HTTP_SERVER_REQUEST_DURATION,
)
from opentelemetry.util.http import (
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS,
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST,
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE,
    SanitizeValue,
    _parse_url_query,
    get_custom_headers,
    get_excluded_urls,
    normalise_request_header_name,
    normalise_response_header_name,
    redact_query_parameters,
    redact_url,
    sanitize_method,
)

tracer = None
meter_old = None
meter_new = None
duration_histogram_old = None
duration_histogram_new = None
active_requests_counter = None
_excluded_urls = None
_sem_conv_opt_in_mode = _StabilityMode.DEFAULT


def _parse_active_request_count_attrs(
    req_attrs, sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT
):
    return _filter_semconv_active_request_count_attr(
        req_attrs,
        _server_active_requests_count_attrs_old,
        _server_active_requests_count_attrs_new,
        sem_conv_opt_in_mode,
    )


def _parse_duration_attrs(
    req_attrs: dict[str, str | None],
    sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT,
):
    return _filter_semconv_duration_attrs(
        req_attrs,
        _server_duration_attrs_old,
        _server_duration_attrs_new,
        sem_conv_opt_in_mode,
    )


def get_default_span_name(request: web.Request) -> str:
    """Default implementation for get_default_span_details
    Args:
        request: the request object itself.
    Returns:
        The span name.
    """
    span_name = request.path.strip() or f"HTTP {request.method}"
    return span_name


def _get_view_func(request: web.Request) -> str:
    """Returns the name of the request handler.
    Args:
        request: the request object itself.
    Returns:
        a string containing the name of the handler function
    """
    try:
        return request.match_info.handler.__name__
    except AttributeError:
        return "unknown"


def collect_request_attributes(
    request: web.Request,
    sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT,
) -> dict:
    """Collects HTTP request attributes from the aiohttp request context
    and returns a dictionary to be used as span creation attributes."""

    result: dict[str, str | None] = {}

    _set_http_method(
        result,
        request.method,
        sanitize_method(request.method),
        sem_conv_opt_in_mode,
    )
    _set_http_scheme(
        result,
        request.scheme,
        sem_conv_opt_in_mode,
    )

    server_host = request.url.host
    port = request.url.port
    if server_host:
        _set_http_net_host(result, server_host, sem_conv_opt_in_mode)
        if _report_old(sem_conv_opt_in_mode):
            result[HTTP_HOST] = server_host
    if port:
        _set_http_net_host_port(result, port, sem_conv_opt_in_mode)

    if request.path_qs:
        redacted_target = redact_query_parameters(request.path_qs)
        _, redacted_query = _parse_url_query(redacted_target)
        _set_http_target(
            result,
            redacted_target,
            request.path,
            redacted_query,
            sem_conv_opt_in_mode,
        )

    # old semconv v1.20.0 - always set HTTP_URL when reporting old semconv
    if _report_old(sem_conv_opt_in_mode):
        result[HTTP_URL] = redact_url(str(request.url))

    if user_agent := request.headers.get("user-agent"):
        _set_http_user_agent(result, user_agent, sem_conv_opt_in_mode)

    flavor = f"{request.version.major}.{request.version.minor}"
    _set_http_flavor_version(result, flavor, sem_conv_opt_in_mode)

    # http.route for both old and new
    result[HTTP_ROUTE] = _get_view_func(request)

    if _report_old(sem_conv_opt_in_mode):
        http_host_value_list = (
            [request.host]
            if not isinstance(request.host, list)
            else request.host
        )
        if http_host_value_list:
            result[HTTP_SERVER_NAME] = ",".join(http_host_value_list)

    return result


def collect_request_headers_attributes(
    request: web.Request,
) -> dict[str, list[str]]:
    sanitize = SanitizeValue(
        get_custom_headers(
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS
        )
    )

    return sanitize.sanitize_header_values(
        request.headers,
        get_custom_headers(
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST
        ),
        normalise_request_header_name,
    )


def collect_response_headers_attributes(
    response: web.Response,
) -> dict[str, list[str]]:
    sanitize = SanitizeValue(
        get_custom_headers(
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS
        )
    )

    return sanitize.sanitize_header_values(
        response.headers,
        get_custom_headers(
            OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE
        ),
        normalise_response_header_name,
    )


def set_status_code(
    span: trace.Span,
    status_code: int,
    duration_attrs: dict[str, str | None] | None = None,
    sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT,
) -> None:
    """Adds HTTP response attributes to span using the status_code argument."""
    if duration_attrs is None:
        duration_attrs = {}

    status_code_str = str(status_code)

    try:
        status_code_int = int(status_code)
    except ValueError:
        status_code_int = -1

    _set_status(
        span,
        duration_attrs,
        status_code_int,
        status_code_str,
        server_span=True,
        sem_conv_opt_in_mode=sem_conv_opt_in_mode,
    )


class AiohttpGetter(Getter):
    """Extract current trace from headers"""

    def get(self, carrier, key: str) -> list | None:
        """Getter implementation to retrieve an HTTP header value from the aiohttp
        request context.

        Args:
            carrier: aiohttp request context object
            key: header name in request context
        Returns:
            A list of all header values matching the key, or None if the key
            does not match any header.
        """
        headers: CIMultiDictProxy = carrier.headers
        if not headers:
            return None
        return headers.getall(key, None)

    def keys(self, carrier: dict) -> list:
        return list(carrier.keys())


getter = AiohttpGetter()


def create_aiohttp_middleware(
    tracer_provider: trace.TracerProvider | None = None,
):
    _tracer = (
        tracer_provider.get_tracer(__name__, __version__)
        if tracer_provider
        else tracer
    )

    @web.middleware
    async def _middleware(request, handler):
        """Middleware for aiohttp implementing tracing logic"""
        if (
            not is_http_instrumentation_enabled()
            or _excluded_urls.url_disabled(request.url.path)
        ):
            return await handler(request)

        span_name = get_default_span_name(request)

        request_attrs = collect_request_attributes(
            request, _sem_conv_opt_in_mode
        )
        active_requests_count_attrs = _parse_active_request_count_attrs(
            request_attrs,
            _sem_conv_opt_in_mode,
        )

        with _tracer.start_as_current_span(
            span_name,
            context=extract(request, getter=getter),
            kind=trace.SpanKind.SERVER,
            attributes=request_attrs,
            set_status_on_exception=False,
            record_exception=False,
        ) as span:
            if span.is_recording():
                span.set_attributes(
                    collect_request_headers_attributes(request)
                )
            start = default_timer()
            active_requests_counter.add(1, active_requests_count_attrs)
            try:
                resp = await handler(request)
                set_status_code(
                    span,
                    resp.status,
                    request_attrs,
                    _sem_conv_opt_in_mode,
                )
                if span.is_recording():
                    response_headers_attributes = (
                        collect_response_headers_attributes(resp)
                    )
                    span.set_attributes(response_headers_attributes)
            except web.HTTPServerError as ex:
                set_status_code(
                    span,
                    ex.status_code,
                    request_attrs,
                    _sem_conv_opt_in_mode,
                )
                span.record_exception(ex)
                raise
            except web.HTTPException as ex:
                set_status_code(
                    span,
                    ex.status_code,
                    request_attrs,
                    _sem_conv_opt_in_mode,
                )
                raise
            except Exception as ex:
                set_status_code(
                    span,
                    type(ex).__qualname__,
                    request_attrs,
                    _sem_conv_opt_in_mode,
                )
                span.record_exception(ex)
                raise
            finally:
                duration_s = default_timer() - start
                if duration_histogram_old:
                    duration_attrs_old = _parse_duration_attrs(
                        request_attrs, _StabilityMode.DEFAULT
                    )
                    duration_histogram_old.record(
                        max(round(duration_s * 1000), 0), duration_attrs_old
                    )
                if duration_histogram_new:
                    duration_attrs_new = _parse_duration_attrs(
                        request_attrs, _StabilityMode.HTTP
                    )
                    duration_histogram_new.record(
                        max(duration_s, 0), duration_attrs_new
                    )
                active_requests_counter.add(-1, active_requests_count_attrs)
            return resp

    return _middleware


middleware = create_aiohttp_middleware()  # for backwards compatibility


def create_instrumented_application(
    tracer_provider: trace.TracerProvider | None = None,
):
    _middleware = create_aiohttp_middleware(tracer_provider=tracer_provider)

    class _InstrumentedApplication(web.Application):
        """Insert tracing middleware"""

        def __init__(self, *args, **kwargs):
            middlewares = kwargs.pop("middlewares", [])
            middlewares.insert(0, _middleware)
            kwargs["middlewares"] = middlewares
            super().__init__(*args, **kwargs)

    return _InstrumentedApplication


class AioHttpServerInstrumentor(BaseInstrumentor):
    # pylint: disable=protected-access,attribute-defined-outside-init
    """An instrumentor for aiohttp.web.Application

    See `BaseInstrumentor`
    """

    def _instrument(self, **kwargs):
        _OpenTelemetrySemanticConventionStability._initialize()
        sem_conv_opt_in_mode = _OpenTelemetrySemanticConventionStability._get_opentelemetry_stability_opt_in_mode(
            _OpenTelemetryStabilitySignalType.HTTP,
        )

        tracer_provider = kwargs.get("tracer_provider", None)
        # update global values at instrument time so we can test them
        global _excluded_urls  # pylint: disable=global-statement
        _excluded_urls = get_excluded_urls("AIOHTTP_SERVER")

        global _sem_conv_opt_in_mode  # pylint: disable=global-statement
        _sem_conv_opt_in_mode = sem_conv_opt_in_mode

        global tracer  # pylint: disable=global-statement
        tracer = trace.get_tracer(
            __name__,
            __version__,
            schema_url=_get_schema_url(sem_conv_opt_in_mode),
        )

        global meter_old  # pylint: disable=global-statement
        global meter_new  # pylint: disable=global-statement
        global duration_histogram_old  # pylint: disable=global-statement
        global duration_histogram_new  # pylint: disable=global-statement
        global active_requests_counter  # pylint: disable=global-statement

        if _report_old(sem_conv_opt_in_mode):
            meter_old = metrics.get_meter(
                __name__,
                __version__,
                schema_url=_get_schema_url(_StabilityMode.DEFAULT),
            )
            duration_histogram_old = meter_old.create_histogram(
                name=MetricInstruments.HTTP_SERVER_DURATION,
                unit="ms",
                description="Measures the duration of inbound HTTP requests.",
            )

        if _report_new(sem_conv_opt_in_mode):
            meter_new = metrics.get_meter(
                __name__,
                __version__,
                schema_url=_get_schema_url(_StabilityMode.HTTP),
            )
            duration_histogram_new = meter_new.create_histogram(
                name=HTTP_SERVER_REQUEST_DURATION,
                unit="s",
                description="Duration of HTTP server requests.",
                explicit_bucket_boundaries_advisory=HTTP_DURATION_HISTOGRAM_BUCKETS_NEW,
            )

        meter_for_counter = meter_new or meter_old
        active_requests_counter = meter_for_counter.create_up_down_counter(
            name=MetricInstruments.HTTP_SERVER_ACTIVE_REQUESTS,
            unit="{request}",
            description="Number of active HTTP server requests.",
        )

        self._original_app = web.Application

        _InstrumentedApplication = create_instrumented_application(
            tracer_provider=tracer_provider
        )
        setattr(web, "Application", _InstrumentedApplication)

    def _uninstrument(self, **kwargs):
        setattr(web, "Application", self._original_app)

    def instrumentation_dependencies(self):
        return _instruments
