# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Rdkafka
      module Patches
        # The Producer module contains the instrumentation patch the Producer#produce method
        module Producer
          def produce(*args, **kwargs)
            topic = kwargs[:topic]
            headers = kwargs[:headers] || {}
            attributes = {
              'messaging.system' => 'kafka',
              'messaging.destination' => topic,
              'messaging.destination_kind' => 'topic'
            }

            tracer.in_span("#{topic} publish", attributes: attributes, kind: :producer) do
              OpenTelemetry.propagation.inject(headers)
              kwargs[:headers] = headers
              super
            end
          end

          private

          def tracer
            Rdkafka::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
