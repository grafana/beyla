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
This library uses OpenTelemetry to track web requests in Tornado applications.

Usage
-----

.. code-block:: python

    import tornado.web
    from opentelemetry.instrumentation.tornado import TornadoInstrumentor

    # apply tornado instrumentation
    TornadoInstrumentor().instrument()

    class Handler(tornado.web.RequestHandler):
        def get(self):
            self.set_status(200)

    app = tornado.web.Application([(r"/", Handler)])
    app.listen(8080)
    tornado.ioloop.IOLoop.current().start()

Configuration
-------------

The following environment variables are supported as configuration options:

- ``OTEL_PYTHON_TORNADO_EXCLUDED_URLS`` (or ``OTEL_PYTHON_EXCLUDED_URLS`` to cover all instrumentations)

A comma separated list of paths that should not be automatically traced. For example, if this is set to

::

    export OTEL_PYTHON_TORNADO_EXCLUDED_URLS='/healthz,/ping'

Then any requests made to ``/healthz`` and ``/ping`` will not be automatically traced.

Request attributes
******************

To extract certain attributes from Tornado's request object and use them as span attributes, set the environment variable ``OTEL_PYTHON_TORNADO_TRACED_REQUEST_ATTRS`` to a comma
delimited list of request attribute names.

For example,

::

    export OTEL_PYTHON_TORNADO_TRACED_REQUEST_ATTRS='uri,query'

will extract path_info and content_type attributes from every traced request and add them as span attributes.

Request/Response hooks
**********************

Tornado instrumentation supports extending tracing behaviour with the help of hooks.
Its ``instrument()`` method accepts three optional functions that get called back with the
created span and some other contextual information. Example:

.. code-block:: python

    from opentelemetry.instrumentation.tornado import TornadoInstrumentor

    # will be called for each incoming request to Tornado
    # web server. `handler` is an instance of
    # `tornado.web.RequestHandler`.
    def server_request_hook(span, handler):
        pass

    # will be called just before sending out a request with
    # `tornado.httpclient.AsyncHTTPClient.fetch`.
    # `request` is an instance of ``tornado.httpclient.HTTPRequest`.
    def client_request_hook(span, request):
        pass

    # will be called after a outgoing request made with
    # `tornado.httpclient.AsyncHTTPClient.fetch` finishes.
    # `response`` is an instance of ``Future[tornado.httpclient.HTTPResponse]`.
    def client_response_hook(span, future):
        pass

    # apply tornado instrumentation with hooks
    TornadoInstrumentor().instrument(
        server_request_hook=server_request_hook,
        client_request_hook=client_request_hook,
        client_response_hook=client_response_hook,
    )

Capture HTTP request and response headers
*****************************************
You can configure the agent to capture predefined HTTP headers as span attributes, according to the `semantic conventions <https://github.com/open-telemetry/semantic-conventions/blob/main/docs/http/http-spans.md#http-server-span>`_.

Request headers
***************
To capture predefined HTTP request headers as span attributes, set the environment variable ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST``
to a comma-separated list of HTTP header names.

For example,

::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST="content-type,custom_request_header"

will extract ``content-type`` and ``custom_request_header`` from request headers and add them as span attributes.

It is recommended that you should give the correct names of the headers to be captured in the environment variable.
Request header names in tornado are case insensitive. So, giving header name as ``CUStomHeader`` in environment variable will be able capture header with name ``customheader``.

The name of the added span attribute will follow the format ``http.request.header.<header_name>`` where ``<header_name>`` being the normalized HTTP header name (lowercase, with - characters replaced by _ ).
The value of the attribute will be single item list containing all the header values.

Example of the added span attribute,
``http.request.header.custom_request_header = ["<value1>,<value2>"]``

Response headers
****************
To capture predefined HTTP response headers as span attributes, set the environment variable ``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE``
to a comma-separated list of HTTP header names.

For example,

::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE="content-type,custom_response_header"

will extract ``content-type`` and ``custom_response_header`` from response headers and add them as span attributes.

It is recommended that you should give the correct names of the headers to be captured in the environment variable.
Response header names captured in tornado are case insensitive. So, giving header name as ``CUStomHeader`` in environment variable will be able capture header with name ``customheader``.

The name of the added span attribute will follow the format ``http.response.header.<header_name>`` where ``<header_name>`` being the normalized HTTP header name (lowercase, with - characters replaced by _ ).
The value of the attribute will be single item list containing all the header values.

Example of the added span attribute,
``http.response.header.custom_response_header = ["<value1>,<value2>"]``

Note:
    Environment variable names to capture http headers are still experimental, and thus are subject to change.

API
---
"""

import urllib
from collections import namedtuple
from functools import partial
from logging import getLogger
from time import time_ns
from timeit import default_timer
from typing import Collection, Dict

import tornado.web
import tornado.websocket
import wrapt
from wrapt import wrap_function_wrapper

from opentelemetry import context, trace
from opentelemetry.instrumentation._semconv import (
    HTTP_DURATION_HISTOGRAM_BUCKETS_NEW,
    _get_schema_url,
    _OpenTelemetrySemanticConventionStability,
    _OpenTelemetryStabilitySignalType,
    _report_new,
    _report_old,
    _set_http_flavor_version,
    _set_http_host_server,
    _set_http_method,
    _set_http_scheme,
    _set_http_target,
    _set_http_url,
    _set_http_user_agent,
    _set_status,
    _StabilityMode,
)
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.propagators import (
    FuncSetter,
    get_global_response_propagator,
)
from opentelemetry.instrumentation.tornado.package import _instruments
from opentelemetry.instrumentation.tornado.version import __version__
from opentelemetry.instrumentation.utils import (
    _start_internal_or_server_span,
    extract_attributes_from_object,
    unwrap,
)
from opentelemetry.metrics import get_meter
from opentelemetry.metrics._internal.instrument import Histogram
from opentelemetry.propagators import textmap
from opentelemetry.semconv._incubating.attributes.http_attributes import (
    HTTP_CLIENT_IP,
    HTTP_FLAVOR,
    HTTP_HOST,
    HTTP_METHOD,
    HTTP_SCHEME,
    HTTP_STATUS_CODE,
    HTTP_TARGET,
)
from opentelemetry.semconv._incubating.attributes.net_attributes import (
    NET_PEER_IP,
)
from opentelemetry.semconv.attributes.client_attributes import (
    CLIENT_ADDRESS,
)
from opentelemetry.semconv.attributes.http_attributes import (
    HTTP_REQUEST_METHOD,
    HTTP_RESPONSE_STATUS_CODE,
)
from opentelemetry.semconv.attributes.network_attributes import (
    NETWORK_PEER_ADDRESS,
    NETWORK_PROTOCOL_VERSION,
)
from opentelemetry.semconv.attributes.url_attributes import (
    URL_PATH,
    URL_QUERY,
    URL_SCHEME,
)
from opentelemetry.semconv.metrics import MetricInstruments
from opentelemetry.util.http import (
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST,
    OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE,
    _parse_url_query,
    get_custom_headers,
    get_excluded_urls,
    get_traced_request_attrs,
    normalise_request_header_name,
    normalise_response_header_name,
    normalize_user_agent,
    redact_url,
    sanitize_method,
)

from .client import fetch_async  # pylint: disable=E0401

_logger = getLogger(__name__)
_TraceContext = namedtuple("TraceContext", ["activation", "span", "token"])
_HANDLER_STATE_KEY = "_otel_state_key"
_HANDLER_CONTEXT_KEY = "_otel_trace_context_key"
_OTEL_PATCHED_KEY = "_otel_patched_key"

_START_TIME = "start_time"

_excluded_urls = get_excluded_urls("TORNADO")
_traced_request_attrs = get_traced_request_attrs("TORNADO")
response_propagation_setter = FuncSetter(tornado.web.RequestHandler.add_header)


class TornadoInstrumentor(BaseInstrumentor):
    patched_handlers = []
    original_handler_new = None

    def __init__(self):
        super().__init__()
        self._sem_conv_opt_in_mode = _StabilityMode.DEFAULT

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs):  # pylint: disable=too-many-locals
        """
        _instrument patches tornado.web.RequestHandler and tornado.httpclient.AsyncHTTPClient classes
        to automatically instrument requests both received and sent by Tornado.

        We don't patch RequestHandler._execute as it causes some issues with contextvars based context.
        Mainly the context fails to detach from within RequestHandler.on_finish() if it is attached inside
        RequestHandler._execute. Same issue plagues RequestHandler.initialize. RequestHandler.prepare works
        perfectly on the other hand as it executes in the same context as on_finish and log_exection which
        are patched to finish a span after a request is served.

        However, we cannot just patch RequestHandler's prepare method because it is supposed to be overridden
        by sub-classes and since the parent prepare method does not do anything special, sub-classes don't
        have to call super() when overriding the method.

        In order to work around this, we patch the __init__ method of RequestHandler and then dynamically patch
        the prepare, on_finish and log_exception methods of the derived classes _only_ the first time we see them.
        Note that the patch does not apply on every single __init__ call, only the first one for the entire
        process lifetime.
        """
        # Initialize semantic conventions opt-in mode
        _OpenTelemetrySemanticConventionStability._initialize()
        sem_conv_opt_in_mode = _OpenTelemetrySemanticConventionStability._get_opentelemetry_stability_opt_in_mode(
            _OpenTelemetryStabilitySignalType.HTTP,
        )
        self._sem_conv_opt_in_mode = sem_conv_opt_in_mode

        tracer_provider = kwargs.get("tracer_provider")
        tracer = trace.get_tracer(
            __name__,
            __version__,
            tracer_provider,
            schema_url=_get_schema_url(sem_conv_opt_in_mode),
        )

        meter_provider = kwargs.get("meter_provider")

        # Create meters for old and new semconv based on opt-in mode
        meter_old = None
        meter_new = None

        if _report_old(sem_conv_opt_in_mode):
            meter_old = get_meter(
                __name__,
                __version__,
                meter_provider,
                schema_url=_get_schema_url(_StabilityMode.DEFAULT),
            )

        if _report_new(sem_conv_opt_in_mode):
            meter_new = get_meter(
                __name__,
                __version__,
                meter_provider,
                schema_url=_get_schema_url(_StabilityMode.HTTP),
            )

        client_histograms = _create_client_histograms(
            meter_old, meter_new, sem_conv_opt_in_mode
        )
        server_histograms = _create_server_histograms(
            meter_old, meter_new, sem_conv_opt_in_mode
        )

        client_request_hook = kwargs.get("client_request_hook", None)
        client_response_hook = kwargs.get("client_response_hook", None)
        server_request_hook = kwargs.get("server_request_hook", None)

        def handler_init(init, handler, args, kwargs):
            cls = handler.__class__
            if patch_handler_class(
                tracer,
                server_histograms,
                cls,
                server_request_hook,
                sem_conv_opt_in_mode,
            ):
                self.patched_handlers.append(cls)
            return init(*args, **kwargs)

        wrap_function_wrapper(
            "tornado.web", "RequestHandler.__init__", handler_init
        )

        duration_old = client_histograms.get("old_duration")
        duration_new = client_histograms.get("new_duration")
        request_size_old = client_histograms.get("old_request_size")
        request_size_new = client_histograms.get("new_request_size")
        response_size_old = client_histograms.get("old_response_size")
        response_size_new = client_histograms.get("new_response_size")

        wrap_function_wrapper(
            "tornado.httpclient",
            "AsyncHTTPClient.fetch",
            partial(
                fetch_async,
                tracer,
                client_request_hook,
                client_response_hook,
                duration_old,
                duration_new,
                request_size_old,
                request_size_new,
                response_size_old,
                response_size_new,
                sem_conv_opt_in_mode,
            ),
        )

    def _uninstrument(self, **kwargs):
        self._sem_conv_opt_in_mode = _StabilityMode.DEFAULT

        unwrap(tornado.web.RequestHandler, "__init__")
        unwrap(tornado.httpclient.AsyncHTTPClient, "fetch")
        for handler in self.patched_handlers:
            unpatch_handler_class(handler)
        self.patched_handlers = []


def _create_server_histograms(
    meter_old, meter_new, sem_conv_opt_in_mode
) -> Dict[str, Histogram]:
    histograms = {}

    # Create old semconv metrics
    if _report_old(sem_conv_opt_in_mode):
        histograms["old_duration"] = meter_old.create_histogram(
            name=MetricInstruments.HTTP_SERVER_DURATION,
            unit="ms",
            description="measures the duration of inbound HTTP requests",
        )
        histograms["old_request_size"] = meter_old.create_histogram(
            name=MetricInstruments.HTTP_SERVER_REQUEST_SIZE,
            unit="By",
            description="measures the size of HTTP request messages (compressed)",
        )
        histograms["old_response_size"] = meter_old.create_histogram(
            name=MetricInstruments.HTTP_SERVER_RESPONSE_SIZE,
            unit="By",
            description="measures the size of HTTP response messages (compressed)",
        )

    # Create new semconv metrics
    if _report_new(sem_conv_opt_in_mode):
        histograms["new_duration"] = meter_new.create_histogram(
            name="http.server.request.duration",
            unit="s",
            description="Duration of HTTP server requests.",
            explicit_bucket_boundaries_advisory=HTTP_DURATION_HISTOGRAM_BUCKETS_NEW,
        )
        histograms["new_request_size"] = meter_new.create_histogram(
            name="http.server.request.body.size",
            unit="By",
            description="Size of HTTP server request bodies.",
        )
        histograms["new_response_size"] = meter_new.create_histogram(
            name="http.server.response.body.size",
            unit="By",
            description="Size of HTTP server response bodies.",
        )

    # Active request counter for old/new semantic conventions same
    # because the attributes are the same for both
    # Use meter_old if available, otherwise meter_new
    active_meter = meter_old if meter_old is not None else meter_new
    if active_meter is not None:
        histograms["active_requests"] = active_meter.create_up_down_counter(
            name=MetricInstruments.HTTP_SERVER_ACTIVE_REQUESTS,
            unit="requests",
            description="measures the number of concurrent HTTP requests that are currently in-flight",
        )

    return histograms


def _create_client_histograms(
    meter_old, meter_new, sem_conv_opt_in_mode
) -> Dict[str, Histogram]:
    histograms = {}

    # Create old semconv metrics
    if _report_old(sem_conv_opt_in_mode):
        histograms["old_duration"] = meter_old.create_histogram(
            name=MetricInstruments.HTTP_CLIENT_DURATION,
            unit="ms",
            description="measures the duration outbound HTTP requests",
        )
        histograms["old_request_size"] = meter_old.create_histogram(
            name=MetricInstruments.HTTP_CLIENT_REQUEST_SIZE,
            unit="By",
            description="measures the size of HTTP request messages (compressed)",
        )
        histograms["old_response_size"] = meter_old.create_histogram(
            name=MetricInstruments.HTTP_CLIENT_RESPONSE_SIZE,
            unit="By",
            description="measures the size of HTTP response messages (compressed)",
        )

    # Create new semconv metrics
    if _report_new(sem_conv_opt_in_mode):
        histograms["new_duration"] = meter_new.create_histogram(
            name="http.client.request.duration",
            unit="s",
            description="Duration of HTTP client requests.",
            explicit_bucket_boundaries_advisory=HTTP_DURATION_HISTOGRAM_BUCKETS_NEW,
        )
        histograms["new_request_size"] = meter_new.create_histogram(
            name="http.client.request.body.size",
            unit="By",
            description="Size of HTTP client request bodies.",
        )
        histograms["new_response_size"] = meter_new.create_histogram(
            name="http.client.response.body.size",
            unit="By",
            description="Size of HTTP client response bodies.",
        )

    return histograms


def patch_handler_class(
    tracer,
    server_histograms,
    cls,
    request_hook=None,
    sem_conv_opt_in_mode=_StabilityMode.DEFAULT,
):
    if getattr(cls, _OTEL_PATCHED_KEY, False):
        return False

    setattr(cls, _OTEL_PATCHED_KEY, True)
    _wrap(
        cls,
        "prepare",
        partial(
            _prepare,
            tracer,
            server_histograms,
            request_hook,
            sem_conv_opt_in_mode,
        ),
    )
    _wrap(
        cls,
        "log_exception",
        partial(
            _log_exception, tracer, server_histograms, sem_conv_opt_in_mode
        ),
    )

    if issubclass(cls, tornado.websocket.WebSocketHandler):
        _wrap(
            cls,
            "on_close",
            partial(
                _websockethandler_on_close,
                tracer,
                server_histograms,
                sem_conv_opt_in_mode,
            ),
        )
    else:
        _wrap(
            cls,
            "on_finish",
            partial(
                _on_finish, tracer, server_histograms, sem_conv_opt_in_mode
            ),
        )
    return True


def unpatch_handler_class(cls):
    if not getattr(cls, _OTEL_PATCHED_KEY, False):
        return

    unwrap(cls, "prepare")
    unwrap(cls, "log_exception")
    if issubclass(cls, tornado.websocket.WebSocketHandler):
        unwrap(cls, "on_close")
    else:
        unwrap(cls, "on_finish")
    delattr(cls, _OTEL_PATCHED_KEY)


def _wrap(cls, method_name, wrapper):
    original = getattr(cls, method_name)
    wrapper = wrapt.FunctionWrapper(original, wrapper)
    wrapt.apply_patch(cls, method_name, wrapper)


def _prepare(
    tracer,
    server_histograms,
    request_hook,
    sem_conv_opt_in_mode,
    func,
    handler,
    args,
    kwargs,
):
    request = handler.request
    otel_handler_state = {
        _START_TIME: default_timer(),
        "exclude_request": _excluded_urls.url_disabled(request.uri),
    }
    setattr(handler, _HANDLER_STATE_KEY, otel_handler_state)

    if otel_handler_state["exclude_request"]:
        return func(*args, **kwargs)

    _record_prepare_metrics(server_histograms, handler, sem_conv_opt_in_mode)

    ctx = _start_span(tracer, handler, sem_conv_opt_in_mode)
    if request_hook:
        request_hook(ctx.span, handler)
    return func(*args, **kwargs)


def _on_finish(
    tracer,
    server_histograms,
    sem_conv_opt_in_mode,
    func,
    handler,
    args,
    kwargs,
):
    try:
        return func(*args, **kwargs)
    finally:
        _record_on_finish_metrics(
            server_histograms, handler, None, sem_conv_opt_in_mode
        )
        _finish_span(tracer, handler, None, sem_conv_opt_in_mode)


def _websockethandler_on_close(
    tracer,
    server_histograms,
    sem_conv_opt_in_mode,
    func,
    handler,
    args,
    kwargs,
):
    try:
        func()
    finally:
        _record_on_finish_metrics(
            server_histograms, handler, None, sem_conv_opt_in_mode
        )
        _finish_span(tracer, handler, None, sem_conv_opt_in_mode)


def _log_exception(
    tracer,
    server_histograms,
    sem_conv_opt_in_mode,
    func,
    handler,
    args,
    kwargs,
):
    error = None
    if len(args) == 3:
        error = args[1]

    _record_on_finish_metrics(
        server_histograms, handler, error, sem_conv_opt_in_mode
    )

    _finish_span(tracer, handler, error, sem_conv_opt_in_mode)
    return func(*args, **kwargs)


def _collect_custom_request_headers_attributes(request_headers):
    custom_request_headers_name = get_custom_headers(
        OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST
    )
    attributes = {}
    for header_name in custom_request_headers_name:
        header_values = request_headers.get(header_name)
        if header_values:
            key = normalise_request_header_name(header_name.lower())
            attributes[key] = [header_values]
    return attributes


def _collect_custom_response_headers_attributes(response_headers):
    custom_response_headers_name = get_custom_headers(
        OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE
    )
    attributes = {}
    for header_name in custom_response_headers_name:
        header_values = response_headers.get(header_name)
        if header_values:
            key = normalise_response_header_name(header_name.lower())
            attributes[key] = [header_values]
    return attributes


def _get_attributes_from_request(request, sem_conv_opt_in_mode):
    attrs = {}

    # Set attributes based on semconv mode
    _set_http_method(
        attrs,
        request.method,
        sanitize_method(request.method),
        sem_conv_opt_in_mode,
    )
    _set_http_scheme(attrs, request.protocol, sem_conv_opt_in_mode)
    _set_http_host_server(attrs, request.host, sem_conv_opt_in_mode)
    uri = redact_url(request.uri)
    _, query = _parse_url_query(uri)
    _set_http_target(
        attrs,
        uri,
        request.path,
        query,
        sem_conv_opt_in_mode,
    )
    _set_http_url(attrs, redact_url(request.uri), sem_conv_opt_in_mode)
    user_agent = request.headers.get("user-agent")
    if user_agent:
        _set_http_user_agent(
            attrs,
            normalize_user_agent(user_agent),
            sem_conv_opt_in_mode,
        )

    # HTTP version
    if request.version:
        _set_http_flavor_version(attrs, request.version, sem_conv_opt_in_mode)

    if request.remote_ip:
        # Client IP address
        # e.g. if Tornado is set to trust X-Forwarded-For headers (xheaders=True)
        if _report_old(sem_conv_opt_in_mode):
            attrs[HTTP_CLIENT_IP] = request.remote_ip
        if _report_new(sem_conv_opt_in_mode):
            attrs[CLIENT_ADDRESS] = request.remote_ip

        # Network peer IP if different from remote_ip
        if hasattr(request.connection, "context") and getattr(
            request.connection.context, "_orig_remote_ip", None
        ):
            if _report_old(sem_conv_opt_in_mode):
                attrs[NET_PEER_IP] = request.connection.context._orig_remote_ip
            if _report_new(sem_conv_opt_in_mode):
                attrs[NETWORK_PEER_ADDRESS] = (
                    request.connection.context._orig_remote_ip
                )

    return extract_attributes_from_object(
        request, _traced_request_attrs, attrs
    )


def _get_default_span_name(request):
    """
    Default span name is the HTTP method and URL path, or just the method.
    https://github.com/open-telemetry/opentelemetry-specification/pull/3165
    https://opentelemetry.io/docs/reference/specification/trace/semantic_conventions/http/#name

    Args:
        request: Tornado request object.
    Returns:
        Default span name.
    """

    path = request.path
    method = request.method
    if method and path:
        return f"{method} {path}"
    return f"{method}"


def _get_full_handler_name(handler):
    klass = type(handler)
    return f"{klass.__module__}.{klass.__qualname__}"


def _start_span(tracer, handler, sem_conv_opt_in_mode) -> _TraceContext:
    attributes = _get_attributes_from_request(
        handler.request, sem_conv_opt_in_mode
    )
    span, token = _start_internal_or_server_span(
        tracer=tracer,
        span_name=_get_default_span_name(handler.request),
        start_time=time_ns(),
        context_carrier=handler.request.headers,
        context_getter=textmap.default_getter,
        attributes=attributes,
    )

    if span.is_recording():
        span.set_attribute("tornado.handler", _get_full_handler_name(handler))
        if span.kind == trace.SpanKind.SERVER:
            custom_attributes = _collect_custom_request_headers_attributes(
                handler.request.headers
            )
            if len(custom_attributes) > 0:
                span.set_attributes(custom_attributes)

    activation = trace.use_span(span, end_on_exit=True)
    activation.__enter__()  # pylint: disable=unnecessary-dunder-call
    ctx = _TraceContext(activation, span, token)
    setattr(handler, _HANDLER_CONTEXT_KEY, ctx)

    # finish handler is called after the response is sent back to
    # the client so it is too late to inject trace response headers
    # there.
    propagator = get_global_response_propagator()
    if propagator:
        propagator.inject(handler, setter=response_propagation_setter)

    return ctx


def _finish_span(tracer, handler, error, sem_conv_opt_in_mode):
    status_code = handler.get_status()
    finish_args = (None, None, None)
    ctx = getattr(handler, _HANDLER_CONTEXT_KEY, None)

    if error:
        if isinstance(error, tornado.web.HTTPError):
            status_code = error.status_code
            if not ctx and status_code == 404:
                ctx = _start_span(tracer, handler, sem_conv_opt_in_mode)
        else:
            status_code = 500
        if status_code >= 500:
            finish_args = (
                type(error),
                error,
                getattr(error, "__traceback__", None),
            )

    if not ctx:
        return

    if ctx.span.is_recording():
        metric_attributes = {}
        _set_status(
            ctx.span,
            metric_attributes,
            status_code,
            str(status_code) if status_code else None,
            server_span=True,
            sem_conv_opt_in_mode=sem_conv_opt_in_mode,
        )
        if ctx.span.is_recording() and ctx.span.kind == trace.SpanKind.SERVER:
            custom_attributes = _collect_custom_response_headers_attributes(
                handler._headers
            )
            if len(custom_attributes) > 0:
                ctx.span.set_attributes(custom_attributes)

    ctx.activation.__exit__(*finish_args)  # pylint: disable=unnecessary-dunder-call
    if ctx.token:
        context.detach(ctx.token)
    delattr(handler, _HANDLER_CONTEXT_KEY)


def _record_prepare_metrics(server_histograms, handler, sem_conv_opt_in_mode):
    request_size = int(handler.request.headers.get("Content-Length", 0))

    # Record old semconv metrics
    if _report_old(sem_conv_opt_in_mode):
        metric_attributes_old = _create_metric_attributes_old(handler)
        server_histograms["old_request_size"].record(
            request_size, attributes=metric_attributes_old
        )
        active_requests_attributes_old = (
            _create_active_requests_attributes_old(handler.request)
        )
        server_histograms["active_requests"].add(
            1, attributes=active_requests_attributes_old
        )

    # Record new semconv metrics
    if _report_new(sem_conv_opt_in_mode):
        metric_attributes_new = _create_metric_attributes_new(handler)
        server_histograms["new_request_size"].record(
            request_size, attributes=metric_attributes_new
        )
        # Don't add to active_requests again if already added in old mode
        if not _report_old(sem_conv_opt_in_mode):
            active_requests_attributes_new = (
                _create_active_requests_attributes_new(handler.request)
            )
            server_histograms["active_requests"].add(
                1, attributes=active_requests_attributes_new
            )


def _record_on_finish_metrics(
    server_histograms, handler, error, sem_conv_opt_in_mode
):
    otel_handler_state = getattr(handler, _HANDLER_STATE_KEY, None) or {}
    if otel_handler_state.get("exclude_request"):
        return
    start_time = otel_handler_state.get(_START_TIME, None) or default_timer()
    elapsed_time_s = default_timer() - start_time
    elapsed_time_ms = round(elapsed_time_s * 1000)

    response_size = int(handler._headers.get("Content-Length", 0))
    status_code = handler.get_status()

    if isinstance(error, tornado.web.HTTPError):
        status_code = error.status_code

    # Record old semconv metrics
    if _report_old(sem_conv_opt_in_mode):
        metric_attributes_old = _create_metric_attributes_old(handler)
        if isinstance(error, tornado.web.HTTPError):
            metric_attributes_old[HTTP_STATUS_CODE] = status_code

        server_histograms["old_response_size"].record(
            response_size, attributes=metric_attributes_old
        )
        server_histograms["old_duration"].record(
            elapsed_time_ms, attributes=metric_attributes_old
        )

        active_requests_attributes_old = (
            _create_active_requests_attributes_old(handler.request)
        )
        server_histograms["active_requests"].add(
            -1, attributes=active_requests_attributes_old
        )

    # Record new semconv metrics
    if _report_new(sem_conv_opt_in_mode):
        metric_attributes_new = _create_metric_attributes_new(handler)
        if isinstance(error, tornado.web.HTTPError):
            metric_attributes_new[HTTP_RESPONSE_STATUS_CODE] = status_code

        server_histograms["new_response_size"].record(
            response_size, attributes=metric_attributes_new
        )
        server_histograms["new_duration"].record(
            elapsed_time_s, attributes=metric_attributes_new
        )

        # Don't subtract from active_requests again if already done in old mode
        if not _report_old(sem_conv_opt_in_mode):
            active_requests_attributes_new = (
                _create_active_requests_attributes_new(handler.request)
            )
            server_histograms["active_requests"].add(
                -1, attributes=active_requests_attributes_new
            )


def _create_active_requests_attributes_old(request):
    """Create metric attributes for active requests using old semconv."""
    metric_attributes = {
        HTTP_METHOD: request.method,
        HTTP_SCHEME: request.protocol,
        HTTP_FLAVOR: request.version,
        HTTP_HOST: request.host,
    }
    metric_attributes[HTTP_TARGET] = request.path
    return metric_attributes


def _create_active_requests_attributes_new(request):
    """Create metric attributes for active requests using new semconv."""
    metric_attributes = {
        HTTP_REQUEST_METHOD: request.method,
        URL_SCHEME: request.protocol,
    }
    if request.version:
        metric_attributes[NETWORK_PROTOCOL_VERSION] = request.version
    return metric_attributes


def _create_metric_attributes_old(handler):
    """Create metric attributes using old semconv."""
    metric_attributes = _create_active_requests_attributes_old(handler.request)
    metric_attributes[HTTP_STATUS_CODE] = handler.get_status()
    return metric_attributes


def _create_metric_attributes_new(handler):
    """Create metric attributes using new semconv."""
    metric_attributes = _create_active_requests_attributes_new(handler.request)
    metric_attributes[HTTP_RESPONSE_STATUS_CODE] = handler.get_status()

    # Add URL path if available
    if handler.request.path:
        # Parse query from path if present
        parsed = urllib.parse.urlparse(handler.request.path)
        if parsed.path:
            metric_attributes[URL_PATH] = parsed.path
        if parsed.query:
            metric_attributes[URL_QUERY] = parsed.query

    return metric_attributes
