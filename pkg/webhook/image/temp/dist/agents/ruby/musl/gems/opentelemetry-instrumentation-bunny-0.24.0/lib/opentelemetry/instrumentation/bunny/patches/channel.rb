# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Bunny
      module Patches
        # The Channel module contains the instrumentation patch the Channel#basic_get, Channel#basic_publish and Channel#handle_frameset methods
        module Channel
          def basic_get(queue, opts = { manual_ack: false })
            attributes = OpenTelemetry::Instrumentation::Bunny::PatchHelpers.basic_attributes(self, connection, '', nil)

            tracer.in_span("#{queue} receive", attributes: attributes, kind: :consumer) do |span, _ctx|
              delivery_info, properties, payload = super

              return [delivery_info, properties, payload] unless delivery_info

              OpenTelemetry::Instrumentation::Bunny::PatchHelpers.trace_enrich_receive_span(span, self, delivery_info, properties)

              [delivery_info, properties, payload]
            end
          end

          def basic_publish(payload, exchange, routing_key, opts = {})
            OpenTelemetry::Instrumentation::Bunny::PatchHelpers.with_send_span(self, tracer, exchange, routing_key) do
              OpenTelemetry::Instrumentation::Bunny::PatchHelpers.inject_context_into_property(opts, :headers)

              super
            end
          end

          # This method is called when rabbitmq pushes messages to subscribed consumers
          def handle_frameset(basic_deliver, properties, content)
            OpenTelemetry::Instrumentation::Bunny::PatchHelpers.trace_enrich_receive_span(OpenTelemetry::Trace.current_span, self, basic_deliver, properties) if basic_deliver

            super
          end

          private

          def tracer
            Bunny::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
