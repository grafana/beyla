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
This library allows tracing HTTP elasticsearch made by the
`elasticsearch <https://elasticsearch-py.readthedocs.io/en/master/>`_ library.

.. warning::
    The elasticsearch package got native OpenTelemetry support since version
    `8.13 <https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/release-notes.html#rn-8-13-0>`_.
    To avoid duplicated tracing this instrumentation disables itself if it finds an elasticsearch client
    that has OpenTelemetry support enabled.

    Please be aware that the two libraries may use a different semantic convention, see
    `elasticsearch documentation <https://www.elastic.co/guide/en/elasticsearch/client/python-api/current/opentelemetry.html>`_.

Usage
-----

.. code-block:: python

    from opentelemetry.instrumentation.elasticsearch import ElasticsearchInstrumentor
    import elasticsearch
    from datetime import datetime

    # instrument elasticsearch
    ElasticsearchInstrumentor().instrument()

    # Using elasticsearch as normal now will automatically generate spans
    es = elasticsearch.Elasticsearch()
    es.index(index='my-index', doc_type='_doc', id=1, body={'my': 'data', 'timestamp': datetime.now()})
    es.get(index='my-index', doc_type='_doc', id=1)

Elasticsearch instrumentation prefixes operation names with the string "Elasticsearch". This
can be changed to a different string by either setting the OTEL_PYTHON_ELASTICSEARCH_NAME_PREFIX
environment variable or by passing the prefix as an argument to the instrumentor. For example,


.. code-block:: python

    from opentelemetry.instrumentation.elasticsearch import ElasticsearchInstrumentor

    ElasticsearchInstrumentor("my-custom-prefix").instrument()

The instrument() method accepts the following keyword args:
tracer_provider (TracerProvider) - an optional tracer provider
request_hook (Callable) - a function with extra user-defined logic to be performed before performing the request
this function signature is:
def request_hook(span: Span, method: str, url: str, kwargs)

response_hook (Callable) - a function with extra user-defined logic to be performed after performing the request
this function signature is:
def response_hook(span: Span, response: dict)

for example:

.. code-block: python

    from opentelemetry.instrumentation.elasticsearch import ElasticsearchInstrumentor
    import elasticsearch
    from datetime import datetime

    def request_hook(span, method, url, kwargs):
        if span and span.is_recording():
            span.set_attribute("custom_user_attribute_from_request_hook", "some-value")

    def response_hook(span, response):
        if span and span.is_recording():
            span.set_attribute("custom_user_attribute_from_response_hook", "some-value")

    # instrument elasticsearch with request and response hooks
    ElasticsearchInstrumentor().instrument(request_hook=request_hook, response_hook=response_hook)

    # Using elasticsearch as normal now will automatically generate spans,
    # including user custom attributes added from the hooks
    es = elasticsearch.Elasticsearch()
    es.index(index='my-index', doc_type='_doc', id=1, body={'my': 'data', 'timestamp': datetime.now()})
    es.get(index='my-index', doc_type='_doc', id=1)

API
---
"""

import re
import warnings
from logging import getLogger
from os import environ
from typing import Collection

import elasticsearch
import elasticsearch.exceptions
from wrapt import wrap_function_wrapper as _wrap

from opentelemetry.instrumentation.elasticsearch.package import _instruments
from opentelemetry.instrumentation.elasticsearch.version import __version__
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import unwrap
from opentelemetry.semconv._incubating.attributes.db_attributes import (
    DB_STATEMENT,
    DB_SYSTEM,
)
from opentelemetry.trace import SpanKind, Status, StatusCode, get_tracer

from .utils import sanitize_body

# Split of elasticsearch and elastic_transport in 8.0.0+
# https://www.elastic.co/guide/en/elasticsearch/client/python-api/master/release-notes.html#rn-8-0-0
es_transport_split = elasticsearch.VERSION[0] > 7
if es_transport_split:
    import elastic_transport
    from elastic_transport._models import DefaultType

logger = getLogger(__name__)


# Values to add as tags from the actual
# payload returned by Elasticsearch, if any.
_ATTRIBUTES_FROM_RESULT = [
    "found",
    "timed_out",
    "took",
]

_DEFAULT_OP_NAME = "request"


class ElasticsearchInstrumentor(BaseInstrumentor):
    """An instrumentor for elasticsearch
    See `BaseInstrumentor`
    """

    def __init__(self, span_name_prefix=None):
        if not span_name_prefix:
            span_name_prefix = environ.get(
                "OTEL_PYTHON_ELASTICSEARCH_NAME_PREFIX",
                "Elasticsearch",
            )
        self._span_name_prefix = span_name_prefix.strip()
        super().__init__()

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs):
        """
        Instruments Elasticsearch module
        """
        tracer_provider = kwargs.get("tracer_provider")
        tracer = get_tracer(
            __name__,
            __version__,
            tracer_provider,
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        request_hook = kwargs.get("request_hook")
        response_hook = kwargs.get("response_hook")
        if es_transport_split:
            _wrap(
                elastic_transport,
                "Transport.perform_request",
                _wrap_perform_request(
                    tracer,
                    self._span_name_prefix,
                    request_hook,
                    response_hook,
                ),
            )
        else:
            _wrap(
                elasticsearch,
                "Transport.perform_request",
                _wrap_perform_request(
                    tracer,
                    self._span_name_prefix,
                    request_hook,
                    response_hook,
                ),
            )

    def _uninstrument(self, **kwargs):
        # pylint: disable=no-member
        transport_class = (
            elastic_transport.Transport
            if es_transport_split
            else elasticsearch.Transport
        )
        unwrap(transport_class, "perform_request")


_regex_doc_url = re.compile(r"/_doc/([^/]+)")

# search api https://www.elastic.co/guide/en/elasticsearch/reference/current/search-search.html
_regex_search_url = re.compile(r"/([^/]+)/_search[/]?")


# pylint: disable=too-many-statements
def _wrap_perform_request(
    tracer,
    span_name_prefix,
    request_hook=None,
    response_hook=None,
):
    # pylint: disable=R0912,R0914
    def wrapper(wrapped, _, args, kwargs):
        # if wrapped elasticsearch has native OTel instrumentation just call the wrapped function
        otel_span = kwargs.get("otel_span")
        if otel_span and otel_span.otel_span:
            warnings.warn(
                "Instrumentation disabled, relying on elasticsearch native OTel support, see "
                "https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation/elasticsearch/elasticsearch.html",
                Warning,
            )
            return wrapped(*args, **kwargs)

        method = url = None
        try:
            method, url, *_ = args
        except IndexError:
            logger.warning(
                "expected perform_request to receive two positional arguments. "
                "Got %d",
                len(args),
            )

        op_name = span_name_prefix + (url or method or _DEFAULT_OP_NAME)

        doc_id = None
        search_target = None

        if url:
            # TODO: This regex-based solution avoids creating an unbounded number of span names, but should be replaced by instrumenting individual Elasticsearch methods instead of Transport.perform_request()
            # A limitation of the regex is that only the '_doc' mapping type is supported. Mapping types are deprecated since Elasticsearch 7
            # https://github.com/open-telemetry/opentelemetry-python-contrib/issues/708
            match = _regex_doc_url.search(url)
            if match is not None:
                # Remove the full document ID from the URL
                doc_span = match.span()
                op_name = (
                    span_name_prefix
                    + url[: doc_span[0]]
                    + "/_doc/:id"
                    + url[doc_span[1] :]
                )
                # Put the document ID in attributes
                doc_id = match.group(1)
            match = _regex_search_url.search(url)
            if match is not None:
                op_name = span_name_prefix + "/<target>/_search"
                search_target = match.group(1)

        params = kwargs.get("params", {})
        body = kwargs.get("body", None)

        with tracer.start_as_current_span(
            op_name,
            kind=SpanKind.CLIENT,
        ) as span:
            if callable(request_hook):
                # elasticsearch 8 changed the parameters quite a bit
                if es_transport_split:

                    def normalize_kwargs(k, v):
                        if isinstance(v, DefaultType):
                            v = str(v)
                        elif isinstance(v, elastic_transport.HttpHeaders):
                            v = dict(v)
                        elif isinstance(
                            v, elastic_transport.OpenTelemetrySpan
                        ):
                            # the transport Span is always a dummy one
                            v = None
                        return (k, v)

                    hook_kwargs = dict(
                        normalize_kwargs(k, v) for k, v in kwargs.items()
                    )
                else:
                    hook_kwargs = kwargs
                request_hook(span, method, url, hook_kwargs)

            if span.is_recording():
                attributes = {
                    DB_SYSTEM: "elasticsearch",
                }
                if url:
                    attributes["elasticsearch.url"] = url
                if method:
                    attributes["elasticsearch.method"] = method
                if body:
                    # Don't set db.statement for bulk requests, as it can be very large
                    if isinstance(body, dict):
                        attributes[DB_STATEMENT] = sanitize_body(body)
                if params:
                    attributes["elasticsearch.params"] = str(params)
                if doc_id:
                    attributes["elasticsearch.id"] = doc_id
                if search_target:
                    attributes["elasticsearch.target"] = search_target
                for key, value in attributes.items():
                    span.set_attribute(key, value)

            rv = wrapped(*args, **kwargs)

            body = rv.body if es_transport_split else rv
            if isinstance(body, dict) and span.is_recording():
                for member in _ATTRIBUTES_FROM_RESULT:
                    if member in body:
                        span.set_attribute(
                            f"elasticsearch.{member}",
                            str(body[member]),
                        )

            # since the transport split the raising of exceptions that set the error status
            # are called after this code so need to set error status manually
            if es_transport_split and span.is_recording():
                if not (method == "HEAD" and rv.meta.status == 404) and (
                    not 200 <= rv.meta.status < 299
                ):
                    exception = elasticsearch.exceptions.HTTP_EXCEPTIONS.get(
                        rv.meta.status, elasticsearch.exceptions.ApiError
                    )
                    message = str(body)
                    if isinstance(body, dict):
                        error = body.get("error", message)
                        if isinstance(error, dict) and "type" in error:
                            error = error["type"]
                        message = error

                    span.set_status(
                        Status(
                            status_code=StatusCode.ERROR,
                            description=f"{exception.__name__}: {message}",
                        )
                    )

            if callable(response_hook):
                response_hook(span, body)
            return rv

    return wrapper
