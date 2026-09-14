from logging import getLogger
from typing import Any, Callable, List, Optional

from pika.adapters.blocking_connection import (
    _ConsumerDeliveryEvt,
    _QueueConsumerGeneratorInfo,
)
from pika.channel import Channel
from pika.spec import Basic, BasicProperties
from wrapt import ObjectProxy

from opentelemetry import context, propagate, trace
from opentelemetry.instrumentation.utils import is_instrumentation_enabled
from opentelemetry.propagators.textmap import CarrierT, Getter
from opentelemetry.semconv._incubating.attributes.net_attributes import (
    NET_PEER_NAME,
    NET_PEER_PORT,
)
from opentelemetry.semconv.trace import (
    MessagingOperationValues,
    SpanAttributes,
)
from opentelemetry.trace import SpanKind, Tracer
from opentelemetry.trace.span import Span

_LOG = getLogger(__name__)


class _PikaGetter(Getter[CarrierT]):  # type: ignore
    def get(self, carrier: CarrierT, key: str) -> Optional[List[str]]:
        value = carrier.get(key, None)
        if value is None:
            return None
        return [value]

    def keys(self, carrier: CarrierT) -> List[str]:
        return []


_pika_getter = _PikaGetter()

HookT = Callable[[Span, bytes, BasicProperties], None]


def dummy_callback(span: Span, body: bytes, properties: BasicProperties): ...


def _decorate_callback(
    callback: Callable[[Channel, Basic.Deliver, BasicProperties, bytes], Any],
    tracer: Tracer,
    task_name: str,
    consume_hook: HookT = dummy_callback,
):
    def decorated_callback(
        channel: Channel,
        method: Basic.Deliver,
        properties: BasicProperties,
        body: bytes,
    ) -> Any:
        if not properties:
            properties = BasicProperties(headers={})
        if properties.headers is None:
            properties.headers = {}
        ctx = propagate.extract(properties.headers, getter=_pika_getter)
        if not ctx:
            ctx = context.get_current()
        token = context.attach(ctx)
        span = _get_span(
            tracer,
            channel,
            properties,
            destination=(
                method.exchange if method.exchange else method.routing_key
            ),
            span_kind=SpanKind.CONSUMER,
            task_name=task_name,
            operation=MessagingOperationValues.RECEIVE,
        )
        try:
            with trace.use_span(span, end_on_exit=True):
                try:
                    consume_hook(span, body, properties)
                except Exception as hook_exception:  # pylint: disable=W0703
                    _LOG.exception(hook_exception)
                retval = callback(channel, method, properties, body)
        finally:
            if token:
                context.detach(token)
        return retval

    return decorated_callback


def _decorate_basic_publish(
    original_function: Callable[[str, str, bytes, BasicProperties, bool], Any],
    channel: Channel,
    tracer: Tracer,
    publish_hook: HookT = dummy_callback,
):
    def decorated_function(
        exchange: str,
        routing_key: str,
        body: bytes,
        properties: BasicProperties = None,
        mandatory: bool = False,
    ) -> Any:
        if not properties:
            properties = BasicProperties(headers={})
        if properties.headers is None:
            properties.headers = {}
        span = _get_span(
            tracer,
            channel,
            properties,
            destination=exchange if exchange else routing_key,
            span_kind=SpanKind.PRODUCER,
            task_name="(temporary)",
            operation=None,
        )
        if not span:
            return original_function(
                exchange, routing_key, body, properties, mandatory
            )
        with trace.use_span(span, end_on_exit=True):
            propagate.inject(properties.headers)
            try:
                publish_hook(span, body, properties)
            except Exception as hook_exception:  # pylint: disable=W0703
                _LOG.exception(hook_exception)
            retval = original_function(
                exchange, routing_key, body, properties, mandatory
            )
        return retval

    return decorated_function


def _get_span(
    tracer: Tracer,
    channel: Optional[Channel],
    properties: BasicProperties,
    task_name: str,
    destination: str,
    span_kind: SpanKind,
    operation: Optional[MessagingOperationValues] = None,
) -> Optional[Span]:
    if not is_instrumentation_enabled():
        return None
    task_name = properties.type if properties.type else task_name
    span = tracer.start_span(
        name=_generate_span_name(destination, operation),
        kind=span_kind,
    )
    if span.is_recording():
        _enrich_span(span, channel, properties, task_name, operation)
    return span


def _generate_span_name(
    task_name: str, operation: Optional[MessagingOperationValues]
) -> str:
    if not operation:
        return f"{task_name} send"
    return f"{task_name} {operation.value}"


def _enrich_span(
    span: Span,
    channel: Optional[Channel],
    properties: BasicProperties,
    task_destination: str,
    operation: Optional[MessagingOperationValues] = None,
) -> None:
    span.set_attribute(SpanAttributes.MESSAGING_SYSTEM, "rabbitmq")
    if operation:
        span.set_attribute(SpanAttributes.MESSAGING_OPERATION, operation.value)
    else:
        span.set_attribute(SpanAttributes.MESSAGING_TEMP_DESTINATION, True)
    span.set_attribute(SpanAttributes.MESSAGING_DESTINATION, task_destination)
    if properties.message_id:
        span.set_attribute(
            SpanAttributes.MESSAGING_MESSAGE_ID, properties.message_id
        )
    if properties.correlation_id:
        span.set_attribute(
            SpanAttributes.MESSAGING_CONVERSATION_ID, properties.correlation_id
        )
    if not channel:
        return
    if not hasattr(channel.connection, "params"):
        span.set_attribute(NET_PEER_NAME, channel.connection._impl.params.host)
        span.set_attribute(NET_PEER_PORT, channel.connection._impl.params.port)
    else:
        span.set_attribute(NET_PEER_NAME, channel.connection.params.host)
        span.set_attribute(NET_PEER_PORT, channel.connection.params.port)


# pylint:disable=abstract-method
class ReadyMessagesDequeProxy(ObjectProxy):
    def __init__(
        self,
        wrapped,
        queue_consumer_generator: _QueueConsumerGeneratorInfo,
        tracer: Optional[Tracer],
        consume_hook: HookT = dummy_callback,
    ):
        super().__init__(wrapped)
        self._self_active_token = None
        self._self_tracer = tracer
        self._self_consume_hook = consume_hook
        self._self_queue_consumer_generator = queue_consumer_generator

    def popleft(self, *args, **kwargs):
        try:
            # end active context if exists
            if self._self_active_token:
                context.detach(self._self_active_token)
        except Exception as inst_exception:  # pylint: disable=W0703
            _LOG.exception(inst_exception)

        evt = self.__wrapped__.popleft(*args, **kwargs)  # pylint:disable=no-member

        try:
            # If a new message was received, create a span and set as active context
            if isinstance(evt, _ConsumerDeliveryEvt):
                method = evt.method
                properties = evt.properties
                if not properties:
                    properties = BasicProperties(headers={})
                if properties.headers is None:
                    properties.headers = {}
                ctx = propagate.extract(
                    properties.headers, getter=_pika_getter
                )
                if not ctx:
                    ctx = context.get_current()
                message_ctx_token = context.attach(ctx)
                span = _get_span(
                    self._self_tracer,
                    None,
                    properties,
                    destination=(
                        method.exchange
                        if method.exchange
                        else method.routing_key
                    ),
                    span_kind=SpanKind.CONSUMER,
                    task_name=self._self_queue_consumer_generator.consumer_tag,
                    operation=MessagingOperationValues.RECEIVE,
                )
                try:
                    if message_ctx_token:
                        context.detach(message_ctx_token)
                    self._self_active_token = context.attach(
                        trace.set_span_in_context(span)
                    )
                    self._self_consume_hook(span, evt.body, properties)
                except Exception as hook_exception:  # pylint: disable=W0703
                    _LOG.exception(hook_exception)
                finally:
                    # We must end the span here, because the next place we can hook
                    # is not the end of the user code, but only when the next message
                    # arrives. we still set this span's context as the active context
                    # so spans created by user code that handles this message will be
                    # children of this one.
                    span.end()
        except Exception as inst_exception:  # pylint: disable=W0703
            _LOG.exception(inst_exception)

        return evt
