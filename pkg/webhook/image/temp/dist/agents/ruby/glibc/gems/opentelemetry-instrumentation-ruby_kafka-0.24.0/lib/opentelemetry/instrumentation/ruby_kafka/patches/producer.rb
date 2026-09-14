# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module RubyKafka
      module Patches
        # The Producer module contains the instrumentation patch the Producer#produce method
        module Producer
          def produce(value, topic:, key: nil, headers: {}, partition: nil, partition_key: nil, create_time: Time.now)
            attributes = {
              'messaging.system' => 'kafka',
              'messaging.destination' => topic,
              'messaging.destination_kind' => 'topic'
            }

            # If trace context is present in headers, extract and use it as parent. If there is _no_ trace context key
            # in the headers, OpenTelemetry.propagation.extract will return an unmodified copy of the current
            # Thread's context, so the next two lines preserve the correct Thread-local context.
            ctx = OpenTelemetry.propagation.extract(headers)
            OpenTelemetry::Context.with_current(ctx) do
              tracer.in_span("#{topic} publish", attributes: attributes, kind: :producer) do
                OpenTelemetry.propagation.inject(headers)
                super
              end
            end
          end

          private

          def tracer
            RubyKafka::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
