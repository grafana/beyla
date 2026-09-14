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

import functools
from time import time_ns

from tornado.httpclient import HTTPError, HTTPRequest

from opentelemetry import trace
from opentelemetry.instrumentation._semconv import (
    _report_new,
    _report_old,
    _set_http_method,
    _set_http_url,
    _set_status,
)
from opentelemetry.propagate import inject
from opentelemetry.semconv._incubating.attributes.http_attributes import (
    HTTP_METHOD,
    HTTP_STATUS_CODE,
    HTTP_URL,
)
from opentelemetry.semconv.attributes.http_attributes import (
    HTTP_REQUEST_METHOD,
    HTTP_RESPONSE_STATUS_CODE,
)
from opentelemetry.semconv.attributes.server_attributes import (
    SERVER_ADDRESS,
    SERVER_PORT,
)
from opentelemetry.semconv.attributes.url_attributes import URL_FULL
from opentelemetry.util.http import redact_url, sanitize_method


def _normalize_request(args, kwargs):
    req = args[0]
    if not isinstance(req, str):
        return (args, kwargs)

    new_kwargs = {}
    for param in ("callback", "raise_error"):
        if param in kwargs:
            new_kwargs[param] = kwargs.pop(param)

    req = HTTPRequest(req, **kwargs)
    new_args = [req]
    new_args.extend(args[1:])
    return (new_args, new_kwargs)


def fetch_async(  # pylint: disable=too-many-locals
    tracer,
    request_hook,
    response_hook,
    duration_histogram_old,
    duration_histogram_new,
    request_size_histogram_old,
    request_size_histogram_new,
    response_size_histogram_old,
    response_size_histogram_new,
    sem_conv_opt_in_mode,
    func,
    _,
    args,
    kwargs,
):
    start_time = time_ns()

    # Return immediately if no args were provided (error)
    # or original_request is set (meaning we are in a redirect step).
    if len(args) == 0 or hasattr(args[0], "original_request"):
        return func(*args, **kwargs)

    # Force the creation of a HTTPRequest object if needed,
    # so we can inject the context into the headers.
    args, kwargs = _normalize_request(args, kwargs)
    request = args[0]

    span = tracer.start_span(
        request.method,
        kind=trace.SpanKind.CLIENT,
        start_time=start_time,
    )
    if request_hook:
        request_hook(span, request)

    if span.is_recording():
        attributes = {}
        _set_http_url(
            attributes, redact_url(request.url), sem_conv_opt_in_mode
        )
        _set_http_method(
            attributes,
            request.method,
            sanitize_method(request.method),
            sem_conv_opt_in_mode,
        )

        for key, value in attributes.items():
            span.set_attribute(key, value)

    with trace.use_span(span):
        inject(request.headers)
        future = func(*args, **kwargs)
        future.add_done_callback(
            functools.partial(
                _finish_tracing_callback,
                span=span,
                response_hook=response_hook,
                duration_histogram_old=duration_histogram_old,
                duration_histogram_new=duration_histogram_new,
                request_size_histogram_old=request_size_histogram_old,
                request_size_histogram_new=request_size_histogram_new,
                response_size_histogram_old=response_size_histogram_old,
                response_size_histogram_new=response_size_histogram_new,
                sem_conv_opt_in_mode=sem_conv_opt_in_mode,
            )
        )
        return future


def _finish_tracing_callback(  # pylint: disable=too-many-locals,too-many-branches
    future,
    span,
    response_hook,
    duration_histogram_old,
    duration_histogram_new,
    request_size_histogram_old,
    request_size_histogram_new,
    response_size_histogram_old,
    response_size_histogram_new,
    sem_conv_opt_in_mode,
):
    response = None
    status_code = None

    exc = future.exception()
    if exc:
        if isinstance(exc, HTTPError):
            response = exc.response
            status_code = exc.code
        else:
            span.record_exception(exc)
    else:
        response = future.result()
        status_code = response.code

    # Set status using semconv helper
    metric_attributes = {}
    _set_status(
        span,
        metric_attributes,
        status_code if status_code is not None else -1,
        str(status_code) if status_code is not None else "Exception",
        server_span=False,
        sem_conv_opt_in_mode=sem_conv_opt_in_mode,
    )

    if response is not None:
        request_size = int(response.request.headers.get("Content-Length", 0))
        response_size = int(response.headers.get("Content-Length", 0))

        # Record old semconv metrics
        if (
            _report_old(sem_conv_opt_in_mode)
            and duration_histogram_old is not None
        ):
            metric_attributes_old = _create_metric_attributes_old(response)
            if duration_histogram_old:
                duration_histogram_old.record(
                    response.request_time, attributes=metric_attributes_old
                )
            if request_size_histogram_old:
                request_size_histogram_old.record(
                    request_size, attributes=metric_attributes_old
                )
            if response_size_histogram_old:
                response_size_histogram_old.record(
                    response_size, attributes=metric_attributes_old
                )

        # Record new semconv metrics (duration in seconds)
        if (
            _report_new(sem_conv_opt_in_mode)
            and duration_histogram_new is not None
        ):
            metric_attributes_new = _create_metric_attributes_new(response)
            # Convert request_time from seconds to seconds (it's already in seconds)
            if duration_histogram_new:
                duration_histogram_new.record(
                    response.request_time, attributes=metric_attributes_new
                )
            if request_size_histogram_new:
                request_size_histogram_new.record(
                    request_size, attributes=metric_attributes_new
                )
            if response_size_histogram_new:
                response_size_histogram_new.record(
                    response_size, attributes=metric_attributes_new
                )

    if response_hook:
        response_hook(span, future)
    span.end()


def _create_metric_attributes_old(response):
    """Create metric attributes using old semconv."""
    metric_attributes = {
        HTTP_STATUS_CODE: response.code,
        HTTP_URL: redact_url(response.request.url),
        HTTP_METHOD: response.request.method,
    }
    return metric_attributes


def _create_metric_attributes_new(response):
    """Create metric attributes using new semconv."""
    metric_attributes = {
        HTTP_RESPONSE_STATUS_CODE: response.code,
        URL_FULL: redact_url(response.request.url),
        HTTP_REQUEST_METHOD: response.request.method,
    }

    # Add server address and port if available
    if hasattr(response.request, "host") and response.request.host:
        host = response.request.host
        if ":" in host:
            server_address, port_str = host.rsplit(":", 1)
            metric_attributes[SERVER_ADDRESS] = server_address
            try:
                metric_attributes[SERVER_PORT] = int(port_str)
            except ValueError:
                pass
        else:
            metric_attributes[SERVER_ADDRESS] = host

    return metric_attributes
