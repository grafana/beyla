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
Usage
-----

.. code-block:: python

    from opentelemetry.instrumentation.starlette import StarletteInstrumentor
    from starlette import applications
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    def home(request):
        return PlainTextResponse("hi")

    app = applications.Starlette(
        routes=[Route("/foobar", home)]
    )
    StarletteInstrumentor.instrument_app(app)

Configuration
-------------

Exclude lists
*************
To exclude certain URLs from tracking, set the environment variable ``OTEL_PYTHON_STARLETTE_EXCLUDED_URLS``
(or ``OTEL_PYTHON_EXCLUDED_URLS`` to cover all instrumentations) to a string of comma delimited regexes that match the
URLs.

For example,

::

    export OTEL_PYTHON_STARLETTE_EXCLUDED_URLS="client/.*/info,healthcheck"

will exclude requests such as ``https://site/client/123/info`` and ``https://site/xyz/healthcheck``.

Request/Response hooks
**********************

This instrumentation supports request and response hooks. These are functions that get called
right after a span is created for a request and right before the span is finished for the response.

- The server request hook is passed a server span and ASGI scope object for every incoming request.
- The client request hook is called with the internal span, and ASGI scope and event when the method ``receive`` is called.
- The client response hook is called with the internal span, and ASGI scope and event when the method ``send`` is called.

For example,

.. code-block:: python

    from opentelemetry.instrumentation.starlette import StarletteInstrumentor
    from opentelemetry.trace import Span
    from typing import Any

    def server_request_hook(span: Span, scope: dict[str, Any]):
        if span and span.is_recording():
            span.set_attribute("custom_user_attribute_from_request_hook", "some-value")

    def client_request_hook(span: Span, scope: dict[str, Any], message: dict[str, Any]):
        if span and span.is_recording():
            span.set_attribute("custom_user_attribute_from_client_request_hook", "some-value")

    def client_response_hook(span: Span, scope: dict[str, Any], message: dict[str, Any]):
        if span and span.is_recording():
            span.set_attribute("custom_user_attribute_from_response_hook", "some-value")

    StarletteInstrumentor().instrument(server_request_hook=server_request_hook, client_request_hook=client_request_hook, client_response_hook=client_response_hook)

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

Request header names in Starlette are case-insensitive. So, giving the header name as ``CUStom-Header`` in the
environment variable will capture the header named ``custom-header``.

Regular expressions may also be used to match multiple headers that correspond to the given pattern.  For example:
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST="Accept.*,X-.*"

Would match all request headers that start with ``Accept`` and ``X-``.

Additionally, the special keyword ``all`` can be used to capture all request headers.
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST="all"

The name of the added span attribute will follow the format ``http.request.header.<header_name>`` where ``<header_name>``
is the normalized HTTP header name (lowercase, with ``-`` replaced by ``_``). The value of the attribute will be a
list containing the header values.

For example:
``http.request.header.custom_request_header = ["<value1>", "<value2>"]``

Response headers
****************
To capture HTTP response headers as span attributes, set the environment variable
``OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE`` to a comma delimited list of HTTP header names.

For example,
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE="content-type,custom_response_header"

will extract ``content-type`` and ``custom_response_header`` from the response headers and add them as span attributes.

Response header names in Starlette are case-insensitive. So, giving the header name as ``CUStom-Header`` in the
environment variable will capture the header named ``custom-header``.

Regular expressions may also be used to match multiple headers that correspond to the given pattern.  For example:
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE="Content.*,X-.*"

Would match all response headers that start with ``Content`` and ``X-``.

Additionally, the special keyword ``all`` can be used to capture all response headers.
::

    export OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_RESPONSE="all"

The name of the added span attribute will follow the format ``http.response.header.<header_name>`` where ``<header_name>``
is the normalized HTTP header name (lowercase, with ``-`` replaced by ``_``). The value of the attribute will be a
list containing the header values.

For example:
``http.response.header.custom_response_header = ["<value1>", "<value2>"]``

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

from typing import TYPE_CHECKING, Any, Collection, cast
from weakref import WeakSet

from starlette import applications
from starlette.routing import Match

from opentelemetry.instrumentation.asgi import OpenTelemetryMiddleware
from opentelemetry.instrumentation.asgi.types import (
    ClientRequestHook,
    ClientResponseHook,
    ServerRequestHook,
)
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.starlette.package import _instruments
from opentelemetry.instrumentation.starlette.version import __version__
from opentelemetry.metrics import MeterProvider, get_meter
from opentelemetry.semconv._incubating.attributes.http_attributes import (
    HTTP_ROUTE,
)
from opentelemetry.trace import TracerProvider, get_tracer
from opentelemetry.util.http import get_excluded_urls

if TYPE_CHECKING:
    from typing import TypedDict, Unpack

    class InstrumentKwargs(TypedDict, total=False):
        tracer_provider: TracerProvider
        meter_provider: MeterProvider
        server_request_hook: ServerRequestHook
        client_request_hook: ClientRequestHook
        client_response_hook: ClientResponseHook


_excluded_urls = get_excluded_urls("STARLETTE")


class StarletteInstrumentor(BaseInstrumentor):
    """An instrumentor for Starlette.

    See `BaseInstrumentor`.
    """

    _original_starlette = None

    @staticmethod
    def instrument_app(
        app: applications.Starlette,
        server_request_hook: ServerRequestHook = None,
        client_request_hook: ClientRequestHook = None,
        client_response_hook: ClientResponseHook = None,
        meter_provider: MeterProvider | None = None,
        tracer_provider: TracerProvider | None = None,
    ):
        """Instrument an uninstrumented Starlette application.

        Args:
            app: The starlette ASGI application callable to forward requests to.
            server_request_hook: Optional callback which is called with the server span and ASGI
                          scope object for every incoming request.
            client_request_hook: Optional callback which is called with the internal span, and ASGI
                          scope and event which are sent as dictionaries for when the method receive is called.
            client_response_hook: Optional callback which is called with the internal span, and ASGI
                          scope and event which are sent as dictionaries for when the method send is called.
            meter_provider: The optional meter provider to use. If omitted
                the current globally configured one is used.
            tracer_provider: The optional tracer provider to use. If omitted
                the current globally configured one is used.
        """
        tracer = get_tracer(
            __name__,
            __version__,
            tracer_provider,
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        meter = get_meter(
            __name__,
            __version__,
            meter_provider,
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        if not getattr(app, "_is_instrumented_by_opentelemetry", False):
            app.add_middleware(
                OpenTelemetryMiddleware,
                excluded_urls=_excluded_urls,
                default_span_details=_get_default_span_details,
                server_request_hook=server_request_hook,
                client_request_hook=client_request_hook,
                client_response_hook=client_response_hook,
                # Pass in tracer/meter to get __name__and __version__ of starlette instrumentation
                tracer=tracer,
                meter=meter,
            )
            app._is_instrumented_by_opentelemetry = True

            # adding apps to set for uninstrumenting
            _InstrumentedStarlette._instrumented_starlette_apps.add(app)

    @staticmethod
    def uninstrument_app(app: applications.Starlette):
        app.user_middleware = [
            x
            for x in app.user_middleware
            if x.cls is not OpenTelemetryMiddleware
        ]
        app.middleware_stack = app.build_middleware_stack()
        app._is_instrumented_by_opentelemetry = False

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs: Unpack[InstrumentKwargs]):
        self._original_starlette = applications.Starlette
        _InstrumentedStarlette._tracer_provider = kwargs.get("tracer_provider")
        _InstrumentedStarlette._server_request_hook = kwargs.get(
            "server_request_hook"
        )
        _InstrumentedStarlette._client_request_hook = kwargs.get(
            "client_request_hook"
        )
        _InstrumentedStarlette._client_response_hook = kwargs.get(
            "client_response_hook"
        )
        _InstrumentedStarlette._meter_provider = kwargs.get("meter_provider")

        applications.Starlette = _InstrumentedStarlette

    def _uninstrument(self, **kwargs: Any):
        """uninstrumenting all created apps by user"""
        for instance in _InstrumentedStarlette._instrumented_starlette_apps:
            self.uninstrument_app(instance)
        _InstrumentedStarlette._instrumented_starlette_apps.clear()
        applications.Starlette = self._original_starlette


class _InstrumentedStarlette(applications.Starlette):
    _tracer_provider: TracerProvider | None = None
    _meter_provider: MeterProvider | None = None
    _server_request_hook: ServerRequestHook = None
    _client_request_hook: ClientRequestHook = None
    _client_response_hook: ClientResponseHook = None
    _instrumented_starlette_apps: WeakSet[applications.Starlette] = WeakSet()

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        tracer = get_tracer(
            __name__,
            __version__,
            _InstrumentedStarlette._tracer_provider,
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        meter = get_meter(
            __name__,
            __version__,
            _InstrumentedStarlette._meter_provider,
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        self.add_middleware(
            OpenTelemetryMiddleware,
            excluded_urls=_excluded_urls,
            default_span_details=_get_default_span_details,
            server_request_hook=_InstrumentedStarlette._server_request_hook,
            client_request_hook=_InstrumentedStarlette._client_request_hook,
            client_response_hook=_InstrumentedStarlette._client_response_hook,
            # Pass in tracer/meter to get __name__and __version__ of starlette instrumentation
            tracer=tracer,
            meter=meter,
        )
        self._is_instrumented_by_opentelemetry = True
        # adding apps to set for uninstrumenting
        _InstrumentedStarlette._instrumented_starlette_apps.add(self)


def _get_route_details(scope: dict[str, Any]) -> str | None:
    """
    Function to retrieve Starlette route from ASGI scope.

    TODO: there is currently no way to retrieve http.route from
    a starlette application from scope.
    See: https://github.com/encode/starlette/pull/804

    Args:
        scope: The ASGI scope that contains the Starlette application in the "app" key.

    Returns:
        The path to the route if found, otherwise None.
    """
    app = cast(applications.Starlette, scope["app"])
    route: str | None = None

    for starlette_route in app.routes:
        match, _ = starlette_route.matches(scope)
        if match == Match.FULL:
            try:
                route = starlette_route.path
            except AttributeError:
                # routes added via host routing won't have a path attribute
                route = scope.get("path")
            break
        if match == Match.PARTIAL:
            route = starlette_route.path
    return route


def _get_default_span_details(
    scope: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Callback to retrieve span name and attributes from ASGI scope.

    Args:
        scope: The ASGI scope that contains the Starlette application in the "app" key.

    Returns:
        A tuple of span name and attributes.
    """
    route = _get_route_details(scope)
    method: str = scope.get("method", "")
    attributes: dict[str, Any] = {}
    if route:
        attributes[HTTP_ROUTE] = route
    if method and route:  # http
        span_name = f"{method} {route}"
    elif route:  # websocket
        span_name = route
    else:  # fallback
        span_name = method
    return span_name, attributes
