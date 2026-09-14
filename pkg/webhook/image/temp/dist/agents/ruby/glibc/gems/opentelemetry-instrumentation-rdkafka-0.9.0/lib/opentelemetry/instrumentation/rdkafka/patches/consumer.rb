# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Rdkafka
      module Patches
        # The Consumer module contains the instrumentation patch for the Consumer class
        module Consumer
          GETTER = Context::Propagation.text_map_getter
          private_constant :GETTER

          def each
            super do |message|
              attributes = {
                'messaging.system' => 'kafka',
                'messaging.destination' => message.topic,
                'messaging.destination_kind' => 'topic',
                'messaging.kafka.partition' => message.partition,
                'messaging.kafka.offset' => message.offset
              }

              message_key = extract_message_key(message.key)
              attributes['messaging.kafka.message_key'] = message_key if message_key

              parent_context = OpenTelemetry.propagation.extract(message.headers, getter: GETTER)
              span_context = OpenTelemetry::Trace.current_span(parent_context).context
              links = [OpenTelemetry::Trace::Link.new(span_context)] if span_context.valid?

              OpenTelemetry::Context.with_current(parent_context) do
                tracer.in_span("#{message.topic} process", links: links, attributes: attributes, kind: :consumer) do
                  yield message
                end
              end
            end
          end

          # each_batch method is deleted in rdkafka-ruby-0.20.0
          # But, rdkafka-ruby-0.19.x and 0.18.x are still maintained
          if Gem::Version.new(::Rdkafka::VERSION) < Gem::Version.new('0.20.0')
            def each_batch(max_items: 100, bytes_threshold: Float::INFINITY, timeout_ms: 250, yield_on_error: false, &block)
              super do |messages, error|
                if messages.empty?
                  yield messages, error
                else
                  attributes = {
                    'messaging.system' => 'kafka',
                    'messaging.destination_kind' => 'topic',
                    'messaging.kafka.message_count' => messages.size
                  }

                  links = messages.map do |message|
                    trace_context = OpenTelemetry.propagation.extract(message.headers, getter: GETTER)
                    span_context = OpenTelemetry::Trace.current_span(trace_context).context
                    OpenTelemetry::Trace::Link.new(span_context) if span_context.valid?
                  end
                  links.compact!

                  tracer.in_span('batch process', attributes: attributes, links: links, kind: :consumer) do
                    yield messages, error
                  end
                end
              end
            end
          end

          private

          def tracer
            Rdkafka::Instrumentation.instance.tracer
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
  end
end
