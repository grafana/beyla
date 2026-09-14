# frozen_string_literal: true

module OpenTelemetry
  module Instrumentation
    # This class contains the ASN subsciber that instruments message processing
    class ProcessMessageSubscriber
      GETTER = if Gem::Version.new(::Rdkafka::VERSION) >= Gem::Version.new('0.13.0')
                 Context::Propagation.text_map_getter
               else
                 OpenTelemetry::Common::Propagation.symbol_key_getter
               end
      private_constant :GETTER

      def tracer
        Racecar::Instrumentation.instance.tracer
      end

      def start(_name, _id, payload)
        attrs = attributes(payload)

        parent_context = OpenTelemetry.propagation.extract(payload[:headers], getter: GETTER)
        parent_token = OpenTelemetry::Context.attach(parent_context)

        span_context = OpenTelemetry::Trace.current_span(parent_context).context
        links = [OpenTelemetry::Trace::Link.new(span_context)] if span_context.valid?

        span = tracer.start_span("#{payload[:topic]} process", kind: :consumer, attributes: attrs, links: links)
        token = OpenTelemetry::Context.attach(OpenTelemetry::Trace.context_with_span(span))
        payload.merge!(
          __opentelemetry_span: span,
          __opentelemetry_ctx_token: token,
          __opentelemetry_parent_ctx_token: parent_token
        )
      end

      def attributes(payload)
        attributes = {
          'messaging.system' => 'kafka',
          'messaging.destination' => payload[:topic],
          'messaging.destination_kind' => 'topic',
          'messaging.kafka.partition' => payload[:partition],
          'messaging.kafka.offset' => payload[:offset]
        }

        message_key = extract_message_key(payload[:key])
        attributes['messaging.kafka.message_key'] = message_key if message_key

        attributes
      end

      def finish(name, id, payload)
        span = payload.delete(:__opentelemetry_span)
        token = payload.delete(:__opentelemetry_ctx_token)
        parent_token = payload.delete(:__opentelemetry_parent_ctx_token)
        return unless span && token

        if (e = payload[:exception_object])
          span.record_exception(e)
          span.status = OpenTelemetry::Trace::Status.error("Unhandled exception of type: #{e.class}")
        end

        span.finish
        OpenTelemetry::Context.detach(token)
        OpenTelemetry::Context.detach(parent_token)
      end

      def extract_message_key(key)
        # skip encode if already valid utf8
        return key if key.nil? || (key.encoding == Encoding::UTF_8 && key.valid_encoding?)

        key.encode(Encoding::UTF_8)
      rescue Encoding::UndefinedConversionError
        nil
      end
    end
  end
end
