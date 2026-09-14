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
Instrument `click`_ CLI applications. The instrumentor will avoid instrumenting
well-known servers (e.g. *flask run* and *uvicorn*) to avoid unexpected effects
like every request having the same Trace ID.

.. _click: https://pypi.org/project/click/

Usage
-----

.. code-block:: python

    import click
    from opentelemetry.instrumentation.click import ClickInstrumentor

    ClickInstrumentor().instrument()

    @click.command()
    def hello():
       click.echo(f'Hello world!')

    if __name__ == "__main__":
        hello()

API
---
"""

import os
import sys
from functools import partial
from logging import getLogger
from typing import Collection

import click
from wrapt import wrap_function_wrapper

try:
    from flask.cli import ScriptInfo as FlaskScriptInfo
except ImportError:
    FlaskScriptInfo = None


from opentelemetry import trace
from opentelemetry.instrumentation.click.package import _instruments
from opentelemetry.instrumentation.click.version import __version__
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.utils import (
    unwrap,
)
from opentelemetry.semconv._incubating.attributes.process_attributes import (
    PROCESS_COMMAND_ARGS,
    PROCESS_EXECUTABLE_NAME,
    PROCESS_EXIT_CODE,
    PROCESS_PID,
)
from opentelemetry.semconv.attributes.error_attributes import ERROR_TYPE
from opentelemetry.trace.status import StatusCode

_logger = getLogger(__name__)


def _skip_servers(ctx: click.Context):
    # flask run
    if (
        ctx.info_name == "run"
        and FlaskScriptInfo
        and isinstance(ctx.obj, FlaskScriptInfo)
    ):
        return True
    # uvicorn
    if ctx.info_name == "uvicorn":
        return True
    return False


def _command_invoke_wrapper(wrapped, instance, args, kwargs, tracer):
    # Subclasses of Command include groups and CLI runners, but
    # we only want to instrument the actual commands which are
    # instances of Command itself.
    if instance.__class__ != click.Command:
        return wrapped(*args, **kwargs)

    ctx = args[0]

    # we don't want to create a root span for long running processes like servers
    # otherwise all requests would have the same trace id
    if _skip_servers(ctx):
        return wrapped(*args, **kwargs)

    span_name = ctx.info_name
    span_attributes = {
        PROCESS_COMMAND_ARGS: sys.argv,
        PROCESS_EXECUTABLE_NAME: sys.argv[0],
        PROCESS_EXIT_CODE: 0,
        PROCESS_PID: os.getpid(),
    }

    with tracer.start_as_current_span(
        name=span_name,
        kind=trace.SpanKind.INTERNAL,
        attributes=span_attributes,
    ) as span:
        try:
            return wrapped(*args, **kwargs)
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            if span.is_recording():
                span.set_attribute(ERROR_TYPE, exc.__class__.__qualname__)
                span.set_attribute(
                    PROCESS_EXIT_CODE, getattr(exc, "exit_code", 1)
                )
            raise


class ClickInstrumentor(BaseInstrumentor):
    """An instrumentor for click"""

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments

    def _instrument(self, **kwargs):
        tracer = trace.get_tracer(
            __name__,
            __version__,
            kwargs.get("tracer_provider"),
        )

        wrap_function_wrapper(
            click.core.Command,
            "invoke",
            partial(_command_invoke_wrapper, tracer=tracer),
        )

    def _uninstrument(self, **kwargs):
        unwrap(click.core.Command, "invoke")
