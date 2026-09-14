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
This library allows tracing HTTP requests made by the
`urllib <https://docs.python.org/3/library/urllib>`_ library.

Usage
-----
.. code-block:: python

    from urllib import request
    from opentelemetry.instrumentation.urllib import URLLibInstrumentor

    # You can optionally pass a custom TracerProvider to
    # URLLibInstrumentor().instrument()

    URLLibInstrumentor().instrument()
    req = request.Request('https://postman-echo.com/post', method="POST")
    r = request.urlopen(req)

Configuration
-------------

Request/Response hooks
**********************

The urllib instrumentation supports extending tracing behavior with the help of
request and response hooks. These are functions that are called back by the instrumentation
right after a Span is created for a request and right before the span is finished processing a response respectively.
The hooks can be configured as follows:

.. code:: python

    from http.client import HTTPResponse
    from urllib.request import Request

    from opentelemetry.instrumentation.urllib import URLLibInstrumentor
    from opentelemetry.trace import Span


    def request_hook(span: Span, request: Request):
        pass


    def response_hook(span: Span, request: Request, response: HTTPResponse):
        pass


    URLLibInstrumentor().instrument(
        request_hook=request_hook,
        response_hook=response_hook
    )

Exclude lists
*************

To exclude certain URLs from being tracked, set the environment variable ``OTEL_PYTHON_URLLIB_EXCLUDED_URLS``
(or ``OTEL_PYTHON_EXCLUDED_URLS`` as fallback) with comma delimited regexes representing which URLs to exclude.

For example,

::

    export OTEL_PYTHON_URLLIB_EXCLUDED_URLS="client/.*/info,healthcheck"

will exclude requests such as ``https://site/client/123/info`` and ``https://site/xyz/healthcheck``.

Capture HTTP request and response headers
*****************************************
You can configure the agent to capture specified HTTP headers as span attributes, according to the
`semantic conventions <https://opentelemetry.io/docs/specs/semconv/http/http-spans/#http-client-span>`_.

Request headers
***************
To capture HTTP request headers as span attributes, set the environment variable
``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST`` to a comma delimited list of HTTP header names.

For example using the environment variable,
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST="content-type,custom_request_header"

will extract ``content-type`` and ``custom_request_header`` from the request headers and add them as span attributes.

Request header names in urllib are case-insensitive. So, giving the header name as ``CUStom-Header`` in the environment
variable will capture the header named ``custom-header``.

Regular expressions may also be used to match multiple headers that correspond to the given pattern.  For example:
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST="Accept.*,X-.*"

Would match all request headers that start with ``Accept`` and ``X-``.

To capture all request headers, set ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST`` to ``".*"``.
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST=".*"

The name of the added span attribute will follow the format ``http.request.header.<header_name>`` where ``<header_name>``
is the normalized HTTP header name (lowercase, with ``-`` replaced by ``_``). The value of the attribute will be a
single item list containing all the header values.

For example:
``http.request.header.custom_request_header = ["<value1>", "<value2>"]``

.. note::
   Some headers are injected at a lower level by the ``http.client`` module and so are not captured by this instrumentation

Response headers
****************
To capture HTTP response headers as span attributes, set the environment variable
``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE`` to a comma delimited list of HTTP header names.

For example using the environment variable,
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE="content-type,custom_response_header"

will extract ``content-type`` and ``custom_response_header`` from the response headers and add them as span attributes.

Response header names in urllib are case-insensitive. So, giving the header name as ``CUStom-Header`` in the environment
variable will capture the header named ``custom-header``.

Regular expressions may also be used to match multiple headers that correspond to the given pattern.  For example:
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE="Content.*,X-.*"

Would match all response headers that start with ``Content`` and ``X-``.

To capture all response headers, set ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE`` to ``".*"``.
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE=".*"

The name of the added span attribute will follow the format ``http.response.header.<header_name>`` where ``<header_name>``
is the normalized HTTP header name (lowercase, with ``-`` replaced by ``_``). The value of the attribute will be a
list containing the header values.

For example:
``http.response.header.custom_response_header = ["<value1>", "<value2>"]``

Sanitizing headers
******************
In order to prevent storing sensitive data such as personally identifiable information (PII), session keys, passwords,
etc, set the environment variable ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS``
to a comma delimited list of HTTP header names to be sanitized.

Regexes may be used, and all header names will be matched in a case-insensitive manner.

For example using the environment variable,
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS=".*session.*,set-cookie"

will replace the value of headers such as ``session-id`` and ``set-cookie`` with ``[REDACTED]`` in the span.

Note:
    The environment variable names used to capture HTTP headers are still experimental, and thus are subject to change.

API
---
"""

from __future__ import annotations

import functools
import types
import typing
from http import client
from timeit import default_timer
from typing import Any, Collection
from urllib.request import (  # pylint: disable=no-name-in-module,import-error
    OpenerDirector,
    Request,
)

from opentelemetry.instrumentation._semconv import (
    HTTP_DURATION_HISTOGRAM_BUCKETS_NEW,
    _client_duration_attrs_new,
    _client_duration_attrs_old,
    _filter_semconv_duration_attrs,
    _get_schema_url,
    _OpenTelemetrySemanticConventionStability,
    _OpenTelemetryStabilitySignalType,
    _report_new,
    _report_old,
    _set_http_method,
    _set_http_network_protocol_version,
    _set_http_url,
    _set_status,
    _StabilityMode,
)
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.urllib.package import _instruments
from opentelemetry.instrumentation.urllib.version import __version__
from opentelemetry.instrumentation.utils import (
    is_http_instrumentation_enabled,
    suppress_http_instrumentation,
)
from opentelemetry.metrics import Histogram, Meter, get_meter
from opentelemetry.propagate import inject
from opentelemetry.semconv._incubating.attributes.http_attributes import (
    HTTP_URL,
)
from opentelemetry.semconv._incubating.metrics.http_metrics import (
    HTTP_CLIENT_REQUEST_BODY_SIZE,
    HTTP_CLIENT_RESPONSE_BODY_SIZE,
    create_http_client_request_body_size,
    create_http_client_response_body_size,
)
from opentelemetry.semconv.attributes.error_attributes import ERROR_TYPE
from opentelemetry.semconv.metrics import MetricInstruments
from opentelemetry.semconv.metrics.http_metrics import (
    HTTP_CLIENT_REQUEST_DURATION,
)
from opentelemetry.trace import Span, SpanKind, Tracer, get_tracer
from opentelemetry.util.http import (
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST,
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE,
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS,
    ExcludeList,
    get_custom_header_attributes,
    get_custom_headers,
    get_excluded_urls,
    normalise_request_header_name,
    normalise_response_header_name,
    parse_excluded_urls,
    redact_url,
    sanitize_method,
)
from opentelemetry.util.types import Attributes

_excluded_urls_from_env = get_excluded_urls("URLLIB")

_RequestHookT = typing.Optional[typing.Callable[[Span, Request], None]]
_ResponseHookT = typing.Optional[
    typing.Callable[[Span, Request, client.HTTPResponse], None]
]


class URLLibInstrumentor(BaseInstrumentor):
    """An instrumentor for urllib
    See `BaseInstrumentor`
    """

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs: Any):
        """Instruments urllib module

        Args:
            **kwargs: Optional arguments
                ``tracer_provider``: a TracerProvider, defaults to global
                ``request_hook``: An optional callback invoked that is invoked right after a span is created.
                ``response_hook``: An optional callback which is invoked right before the span is finished processing a response
                ``excluded_urls``: A string containing a comma-delimited
                    list of regexes used to exclude URLs from tracking
                ``captured_request_headers``: A comma-separated list of regexes to match against request headers to capture
                ``captured_response_headers``: A comma-separated list of regexes to match against response headers to capture
                ``sensitive_headers``: A comma-separated list of regexes to match against captured headers to be sanitized
        """
        # initialize semantic conventions opt-in if needed
        _OpenTelemetrySemanticConventionStability._initialize()
        sem_conv_opt_in_mode = _OpenTelemetrySemanticConventionStability._get_opentelemetry_stability_opt_in_mode(
            _OpenTelemetryStabilitySignalType.HTTP,
        )
        schema_url = _get_schema_url(sem_conv_opt_in_mode)
        tracer_provider = kwargs.get("tracer_provider")
        tracer = get_tracer(
            __name__,
            __version__,
            tracer_provider,
            schema_url=schema_url,
        )
        excluded_urls = kwargs.get("excluded_urls")
        meter_provider = kwargs.get("meter_provider")
        meter = get_meter(
            __name__,
            __version__,
            meter_provider,
            schema_url=schema_url,
        )

        histograms = _create_client_histograms(meter, sem_conv_opt_in_mode)

        _instrument(
            tracer,
            histograms,
            request_hook=kwargs.get("request_hook"),
            response_hook=kwargs.get("response_hook"),
            excluded_urls=(
                _excluded_urls_from_env
                if excluded_urls is None
                else parse_excluded_urls(excluded_urls)
            ),
            sem_conv_opt_in_mode=sem_conv_opt_in_mode,
            captured_request_headers=kwargs.get(
                "captured_request_headers",
                get_custom_headers(
                    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_REQUEST
                ),
            ),
            captured_response_headers=kwargs.get(
                "captured_response_headers",
                get_custom_headers(
                    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_CLIENT_RESPONSE
                ),
            ),
            sensitive_headers=kwargs.get(
                "sensitive_headers",
                get_custom_headers(
                    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SANITIZE_FIELDS
                ),
            ),
        )

    def _uninstrument(self, **kwargs: Any):
        _uninstrument()

    def uninstrument_opener(self, opener: OpenerDirector):  # pylint: disable=no-self-use
        """uninstrument_opener a specific instance of urllib.request.OpenerDirector"""
        _uninstrument_from(opener, restore_as_bound_func=True)


# pylint: disable=too-many-statements
def _instrument(
    tracer: Tracer,
    histograms: dict[str, Histogram],
    request_hook: _RequestHookT = None,
    response_hook: _ResponseHookT = None,
    excluded_urls: ExcludeList | None = None,
    sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT,
    captured_request_headers: list[str] | None = None,
    captured_response_headers: list[str] | None = None,
    sensitive_headers: list[str] | None = None,
):
    """Enables tracing of all requests calls that go through
    :code:`urllib.Client._make_request`"""

    opener_open = OpenerDirector.open

    @functools.wraps(opener_open)
    def instrumented_open(opener, fullurl, data=None, timeout=None):
        if isinstance(fullurl, str):
            # in case of multiple entries for the same header Opener.open sends the first value
            request_ = Request(
                fullurl, data, headers=dict(reversed(opener.addheaders))
            )
        else:
            request_ = fullurl

        def get_or_create_headers():
            return getattr(request_, "headers", {})

        def call_wrapped():
            return opener_open(opener, request_, data=data, timeout=timeout)

        return _instrumented_open_call(
            opener, request_, call_wrapped, get_or_create_headers
        )

    def _instrumented_open_call(
        _, request, call_wrapped, get_or_create_headers
    ):  # pylint: disable=too-many-locals
        if not is_http_instrumentation_enabled():
            return call_wrapped()

        url = request.full_url
        if excluded_urls and excluded_urls.url_disabled(url):
            return call_wrapped()

        method = request.get_method().upper()

        span_name = _get_span_name(method)

        url = redact_url(url)

        data = getattr(request, "data", None)
        request_size = 0 if data is None else len(data)

        labels = {}

        _set_http_method(
            labels,
            method,
            sanitize_method(method),
            sem_conv_opt_in_mode,
        )
        _set_http_url(labels, url, sem_conv_opt_in_mode)

        headers = get_or_create_headers()
        labels.update(
            get_custom_header_attributes(
                headers,
                captured_request_headers,
                sensitive_headers,
                normalise_request_header_name,
            )
        )

        with tracer.start_as_current_span(
            span_name, kind=SpanKind.CLIENT, attributes=labels
        ) as span:
            exception = None
            if callable(request_hook):
                request_hook(span, request)

            inject(headers)

            with suppress_http_instrumentation():
                start_time = default_timer()
                try:
                    result = call_wrapped()  # *** PROCEED
                except Exception as exc:  # pylint: disable=W0703
                    exception = exc
                    result = getattr(exc, "file", None)
                finally:
                    duration_s = default_timer() - start_time
            response_size = 0
            if result is not None:
                response_size = int(result.headers.get("Content-Length", 0))
                code_ = result.getcode()
                # set http status code based on semconv
                if code_:
                    _set_status_code_attribute(
                        span, code_, labels, sem_conv_opt_in_mode
                    )

                ver_ = str(getattr(result, "version", ""))
                if ver_:
                    _set_http_network_protocol_version(
                        labels, f"{ver_[:1]}.{ver_[:-1]}", sem_conv_opt_in_mode
                    )

                if span.is_recording():
                    span.set_attributes(
                        get_custom_header_attributes(
                            result.headers,
                            captured_response_headers,
                            sensitive_headers,
                            normalise_response_header_name,
                        )
                    )

            if exception is not None and _report_new(sem_conv_opt_in_mode):
                span.set_attribute(ERROR_TYPE, type(exception).__qualname__)
                labels[ERROR_TYPE] = type(exception).__qualname__

            duration_attrs_old = _filter_semconv_duration_attrs(
                labels,
                _client_duration_attrs_old,
                _client_duration_attrs_new,
                sem_conv_opt_in_mode=_StabilityMode.DEFAULT,
            )
            duration_attrs_new = _filter_semconv_duration_attrs(
                labels,
                _client_duration_attrs_old,
                _client_duration_attrs_new,
                sem_conv_opt_in_mode=_StabilityMode.HTTP,
            )

            duration_attrs_old[HTTP_URL] = url

            _record_histograms(
                histograms,
                duration_attrs_old,
                duration_attrs_new,
                request_size,
                response_size,
                duration_s,
                sem_conv_opt_in_mode,
            )

            if callable(response_hook):
                response_hook(span, request, result)

            if exception is not None:
                raise exception.with_traceback(exception.__traceback__)

        return result

    instrumented_open.opentelemetry_instrumentation_urllib_applied = True
    OpenerDirector.open = instrumented_open


def _uninstrument():
    """Disables instrumentation of :code:`urllib` through this module.

    Note that this only works if no other module also patches urllib."""
    _uninstrument_from(OpenerDirector)


def _uninstrument_from(instr_root, restore_as_bound_func: bool = False):
    instr_func_name = "open"
    instr_func = getattr(instr_root, instr_func_name)
    if not getattr(
        instr_func,
        "opentelemetry_instrumentation_urllib_applied",
        False,
    ):
        return

    original = instr_func.__wrapped__  # pylint:disable=no-member
    if restore_as_bound_func:
        original = types.MethodType(original, instr_root)
    setattr(instr_root, instr_func_name, original)


def _get_span_name(method: str) -> str:
    method = sanitize_method(method.strip())
    if method == "_OTHER":
        method = "HTTP"
    return method


def _set_status_code_attribute(
    span: Span,
    status_code: int,
    metric_attributes: dict[str, Any] | None = None,
    sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT,
) -> None:
    status_code_str = str(status_code)
    try:
        status_code = int(status_code)
    except ValueError:
        status_code = -1

    if metric_attributes is None:
        metric_attributes = {}

    _set_status(
        span,
        metric_attributes,
        status_code,
        status_code_str,
        server_span=False,
        sem_conv_opt_in_mode=sem_conv_opt_in_mode,
    )


def _create_client_histograms(
    meter: Meter, sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT
) -> dict[str, Histogram]:
    histograms = {}
    if _report_old(sem_conv_opt_in_mode):
        histograms[MetricInstruments.HTTP_CLIENT_DURATION] = (
            meter.create_histogram(
                name=MetricInstruments.HTTP_CLIENT_DURATION,
                unit="ms",
                description="Measures the duration of the outbound HTTP request",
            )
        )
        histograms[MetricInstruments.HTTP_CLIENT_REQUEST_SIZE] = (
            meter.create_histogram(
                name=MetricInstruments.HTTP_CLIENT_REQUEST_SIZE,
                unit="By",
                description="Measures the size of HTTP request messages.",
            )
        )
        histograms[MetricInstruments.HTTP_CLIENT_RESPONSE_SIZE] = (
            meter.create_histogram(
                name=MetricInstruments.HTTP_CLIENT_RESPONSE_SIZE,
                unit="By",
                description="Measures the size of HTTP response messages.",
            )
        )
    if _report_new(sem_conv_opt_in_mode):
        histograms[HTTP_CLIENT_REQUEST_DURATION] = meter.create_histogram(
            name=HTTP_CLIENT_REQUEST_DURATION,
            unit="s",
            description="Duration of HTTP client requests.",
            explicit_bucket_boundaries_advisory=HTTP_DURATION_HISTOGRAM_BUCKETS_NEW,
        )
        histograms[HTTP_CLIENT_REQUEST_BODY_SIZE] = (
            create_http_client_request_body_size(meter)
        )
        histograms[HTTP_CLIENT_RESPONSE_BODY_SIZE] = (
            create_http_client_response_body_size(meter)
        )

    return histograms


def _record_histograms(
    histograms: dict[str, Histogram],
    metric_attributes_old: Attributes,
    metric_attributes_new: Attributes,
    request_size: int,
    response_size: int,
    duration_s: float,
    sem_conv_opt_in_mode: _StabilityMode = _StabilityMode.DEFAULT,
):
    if _report_old(sem_conv_opt_in_mode):
        duration = max(round(duration_s * 1000), 0)
        histograms[MetricInstruments.HTTP_CLIENT_DURATION].record(
            duration, attributes=metric_attributes_old
        )
        histograms[MetricInstruments.HTTP_CLIENT_REQUEST_SIZE].record(
            request_size, attributes=metric_attributes_old
        )
        histograms[MetricInstruments.HTTP_CLIENT_RESPONSE_SIZE].record(
            response_size, attributes=metric_attributes_old
        )
    if _report_new(sem_conv_opt_in_mode):
        histograms[HTTP_CLIENT_REQUEST_DURATION].record(
            duration_s, attributes=metric_attributes_new
        )
        histograms[HTTP_CLIENT_REQUEST_BODY_SIZE].record(
            request_size, attributes=metric_attributes_new
        )
        histograms[HTTP_CLIENT_RESPONSE_BODY_SIZE].record(
            response_size, attributes=metric_attributes_new
        )
