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
# pylint: disable=unnecessary-dunder-call

from logging import getLogger
from typing import Any, Collection, Dict, Optional, Union

import pika
import wrapt
from packaging import version
from pika.adapters import BlockingConnection
from pika.adapters.blocking_connection import (
    BlockingChannel,
    _QueueConsumerGeneratorInfo,
)
from pika.channel import Channel
from pika.connection import Connection

from opentelemetry import trace
from opentelemetry.instrumentation.instrumentor import BaseInstrumentor
from opentelemetry.instrumentation.pika import utils
from opentelemetry.instrumentation.pika.package import _instruments
from opentelemetry.instrumentation.pika.version import __version__
from opentelemetry.instrumentation.utils import unwrap
from opentelemetry.trace import Tracer, TracerProvider

_LOG = getLogger(__name__)
_CTX_KEY = "__otel_task_span"

_FUNCTIONS_TO_UNINSTRUMENT = ["basic_publish"]


def _consumer_callback_attribute_name() -> str:
    pika_version = version.parse(pika.__version__)
    return (
        "on_message_callback"
        if pika_version >= version.parse("1.0.0")
        else "consumer_cb"
    )


class PikaInstrumentor(BaseInstrumentor):  # type: ignore
    CONSUMER_CALLBACK_ATTR = _consumer_callback_attribute_name()

    # pylint: disable=attribute-defined-outside-init
    @staticmethod
    def _instrument_channel_consumers(
        channel: Union[BlockingChannel, Channel],
        tracer: Tracer,
        consume_hook: utils.HookT = utils.dummy_callback,
    ) -> Any:
        consumer_infos = None
        if isinstance(channel, BlockingChannel):
            consumer_infos = channel._consumer_infos
        elif isinstance(channel, Channel):
            consumer_infos = channel._consumers
        for consumer_tag, consumer_info in consumer_infos.items():
            callback_attr = PikaInstrumentor.CONSUMER_CALLBACK_ATTR
            consumer_callback = getattr(consumer_info, callback_attr, None)
            if consumer_callback is None:
                continue
            decorated_callback = utils._decorate_callback(
                consumer_callback,
                tracer,
                consumer_tag,
                consume_hook,
            )

            setattr(
                decorated_callback,
                "_original_callback",
                consumer_callback,
            )
            setattr(consumer_info, callback_attr, decorated_callback)

    @staticmethod
    def _instrument_basic_publish(
        channel: Union[BlockingChannel, Channel],
        tracer: Tracer,
        publish_hook: utils.HookT = utils.dummy_callback,
    ) -> None:
        original_function = getattr(channel, "basic_publish")
        decorated_function = utils._decorate_basic_publish(
            original_function, channel, tracer, publish_hook
        )
        setattr(decorated_function, "_original_function", original_function)
        channel.__setattr__("basic_publish", decorated_function)
        channel.basic_publish = decorated_function

    @staticmethod
    def _instrument_channel_functions(
        channel: Union[BlockingChannel, Channel],
        tracer: Tracer,
        publish_hook: utils.HookT = utils.dummy_callback,
    ) -> None:
        if hasattr(channel, "basic_publish"):
            PikaInstrumentor._instrument_basic_publish(
                channel, tracer, publish_hook
            )

    @staticmethod
    def _uninstrument_channel_functions(
        channel: Union[BlockingChannel, Channel],
    ) -> None:
        for function_name in _FUNCTIONS_TO_UNINSTRUMENT:
            if not hasattr(channel, function_name):
                continue
            function = getattr(channel, function_name)
            if hasattr(function, "_original_function"):
                channel.__setattr__(function_name, function._original_function)
        unwrap(channel, "basic_consume")

    @staticmethod
    # Make sure that the spans are created inside hash them set as parent and not as brothers
    def instrument_channel(
        channel: Union[BlockingChannel, Channel],
        tracer_provider: Optional[TracerProvider] = None,
        publish_hook: utils.HookT = utils.dummy_callback,
        consume_hook: utils.HookT = utils.dummy_callback,
    ) -> None:
        if not hasattr(channel, "_is_instrumented_by_opentelemetry"):
            channel._is_instrumented_by_opentelemetry = False
        if channel._is_instrumented_by_opentelemetry:
            _LOG.warning(
                "Attempting to instrument Pika channel while already instrumented!"
            )
            return
        tracer = trace.get_tracer(
            __name__,
            __version__,
            tracer_provider,
            schema_url="https://opentelemetry.io/schemas/1.11.0",
        )
        PikaInstrumentor._instrument_channel_consumers(
            channel, tracer, consume_hook
        )
        PikaInstrumentor._decorate_basic_consume(channel, tracer, consume_hook)
        PikaInstrumentor._instrument_channel_functions(
            channel, tracer, publish_hook
        )

    @staticmethod
    def uninstrument_channel(channel: BlockingChannel) -> None:
        if (
            not hasattr(channel, "_is_instrumented_by_opentelemetry")
            or not channel._is_instrumented_by_opentelemetry
        ):
            _LOG.error(
                "Attempting to uninstrument Pika channel while already uninstrumented!"
            )
            return

        for consumers_tag, client_info in channel._consumer_infos.items():
            callback_attr = PikaInstrumentor.CONSUMER_CALLBACK_ATTR
            consumer_callback = getattr(client_info, callback_attr, None)
            if hasattr(consumer_callback, "_original_callback"):
                channel._consumer_infos[consumers_tag] = (
                    consumer_callback._original_callback
                )
        PikaInstrumentor._uninstrument_channel_functions(channel)

    def _decorate_channel_function(
        self,
        tracer_provider: Optional[TracerProvider],
        publish_hook: utils.HookT = utils.dummy_callback,
        consume_hook: utils.HookT = utils.dummy_callback,
    ) -> None:
        def wrapper(wrapped, instance, args, kwargs):
            channel = wrapped(*args, **kwargs)
            self.instrument_channel(
                channel,
                tracer_provider=tracer_provider,
                publish_hook=publish_hook,
                consume_hook=consume_hook,
            )
            return channel

        wrapt.wrap_function_wrapper(BlockingConnection, "channel", wrapper)
        wrapt.wrap_function_wrapper(Connection, "channel", wrapper)

    @staticmethod
    def _decorate_basic_consume(
        channel: Union[BlockingChannel, Channel],
        tracer: Optional[Tracer],
        consume_hook: utils.HookT = utils.dummy_callback,
    ) -> None:
        def wrapper(wrapped, instance, args, kwargs):
            return_value = wrapped(*args, **kwargs)
            PikaInstrumentor._instrument_channel_consumers(
                channel, tracer, consume_hook
            )
            return return_value

        wrapt.wrap_function_wrapper(channel, "basic_consume", wrapper)

    @staticmethod
    def _decorate_queue_consumer_generator(
        tracer_provider: Optional[TracerProvider],
        consume_hook: utils.HookT = utils.dummy_callback,
    ) -> None:
        tracer = trace.get_tracer(__name__, __version__, tracer_provider)

        def wrapper(wrapped, instance, args, kwargs):
            res = wrapped(*args, **kwargs)
            instance.pending_events = utils.ReadyMessagesDequeProxy(
                instance.pending_events, instance, tracer, consume_hook
            )
            return res

        wrapt.wrap_function_wrapper(
            _QueueConsumerGeneratorInfo, "__init__", wrapper
        )

    def _instrument(self, **kwargs: Dict[str, Any]) -> None:
        tracer_provider: TracerProvider = kwargs.get("tracer_provider", None)
        publish_hook: utils.HookT = kwargs.get(
            "publish_hook", utils.dummy_callback
        )
        consume_hook: utils.HookT = kwargs.get(
            "consume_hook", utils.dummy_callback
        )

        self.__setattr__("__opentelemetry_tracer_provider", tracer_provider)
        self._decorate_channel_function(
            tracer_provider,
            publish_hook=publish_hook,
            consume_hook=consume_hook,
        )

        self._decorate_queue_consumer_generator(
            tracer_provider, consume_hook=consume_hook
        )

    def _uninstrument(self, **kwargs: Dict[str, Any]) -> None:
        if hasattr(self, "__opentelemetry_tracer_provider"):
            delattr(self, "__opentelemetry_tracer_provider")
        unwrap(BlockingConnection, "channel")
        unwrap(Connection, "channel")
        unwrap(_QueueConsumerGeneratorInfo, "__init__")

    def instrumentation_dependencies(self) -> Collection[str]:
        return _instruments
