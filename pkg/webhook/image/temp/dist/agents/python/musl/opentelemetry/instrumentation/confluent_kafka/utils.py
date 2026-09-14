from logging import getLogger
from typing import List, Optional

from opentelemetry import context, propagate
from opentelemetry.propagators import textmap
from opentelemetry.semconv._incubating.attributes.messaging_attributes import (
    MESSAGING_MESSAGE_ID,
    MESSAGING_OPERATION,
    MESSAGING_SYSTEM,
    MessagingOperationTypeValues,
)
from opentelemetry.semconv.trace import (
    MessagingDestinationKindValues,
    SpanAttributes,
)
from opentelemetry.trace import Link, SpanKind

_LOG = getLogger(__name__)


class KafkaPropertiesExtractor:
    @staticmethod
    def extract_bootstrap_servers(instance):
        return instance.config.get("bootstrap_servers")

    @staticmethod
    def _extract_argument(key, position, default_value, args, kwargs):
        if len(args) > position:
            return args[position]
        return kwargs.get(key, default_value)

    @staticmethod
    def extract_produce_topic(args, kwargs):
        """extract topic from `produce` method arguments in Producer class"""
        return kwargs.get("topic") or (args[0] if args else "unknown")

    @staticmethod
    def extract_produce_headers(args, kwargs):
        """extract headers from `produce` method arguments in Producer class"""
        return KafkaPropertiesExtractor._extract_argument(
            "headers", 6, None, args, kwargs
        )


class KafkaContextGetter(textmap.Getter):
    def get(self, carrier: textmap.CarrierT, key: str) -> Optional[List[str]]:
        if carrier is None:
            return None

        carrier_items = carrier
        if isinstance(carrier, dict):
            carrier_items = carrier.items()

        for item_key, value in carrier_items:
            if item_key == key:
                if value is not None:
                    return [value.decode()]

        return None

    def keys(self, carrier: textmap.CarrierT) -> List[str]:
        if carrier is None:
            return []

        carrier_items = carrier
        if isinstance(carrier, dict):
            carrier_items = carrier.items()
        return [key for (key, value) in carrier_items]


class KafkaContextSetter(textmap.Setter):
    def set(self, carrier: textmap.CarrierT, key: str, value: str) -> None:
        if carrier is None or key is None:
            return

        if value:
            value = value.encode()

        if isinstance(carrier, list):
            carrier.append((key, value))

        if isinstance(carrier, dict):
            carrier[key] = value


_kafka_getter = KafkaContextGetter()


def _end_current_consume_span(instance):
    if instance._current_context_token:
        context.detach(instance._current_context_token)
    instance._current_context_token = None
    instance._current_consume_span.end()
    instance._current_consume_span = None


def _create_new_consume_span(instance, tracer, records):
    links = _get_links_from_records(records)
    instance._current_consume_span = tracer.start_span(
        name=f"{records[0].topic()} process",
        links=links,
        kind=SpanKind.CONSUMER,
    )


def _get_links_from_records(records):
    links = []
    for record in records:
        ctx = propagate.extract(record.headers(), getter=_kafka_getter)
        if ctx:
            for item in ctx.values():
                if hasattr(item, "get_span_context"):
                    links.append(Link(context=item.get_span_context()))

    return links


def _enrich_span(
    span,
    topic,
    partition: Optional[int] = None,
    offset: Optional[int] = None,
    operation: Optional[MessagingOperationTypeValues] = None,
):
    if not span.is_recording():
        return

    span.set_attribute(MESSAGING_SYSTEM, "kafka")
    span.set_attribute(SpanAttributes.MESSAGING_DESTINATION, topic)

    if partition is not None:
        span.set_attribute(SpanAttributes.MESSAGING_KAFKA_PARTITION, partition)

    span.set_attribute(
        SpanAttributes.MESSAGING_DESTINATION_KIND,
        MessagingDestinationKindValues.QUEUE.value,
    )

    if operation:
        span.set_attribute(MESSAGING_OPERATION, operation.value)
    else:
        span.set_attribute(SpanAttributes.MESSAGING_TEMP_DESTINATION, True)

    # https://stackoverflow.com/questions/65935155/identify-and-find-specific-message-in-kafka-topic
    # A message within Kafka is uniquely defined by its topic name, topic partition and offset.
    if partition is not None and offset is not None and topic:
        span.set_attribute(
            MESSAGING_MESSAGE_ID,
            f"{topic}.{partition}.{offset}",
        )


_kafka_setter = KafkaContextSetter()


def _get_span_name(operation: str, topic: str):
    return f"{topic} {operation}"
