# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Racecar
      module Patches
        # This module contains logic to patch Racecar::Consumer
        module Consumer
          def produce(payload, topic:, key: nil, partition: nil, partition_key: nil, headers: nil, create_time: nil)
            attributes = {
              'messaging.system' => 'kafka',
              'messaging.destination' => topic,
              'messaging.destination_kind' => 'topic'
            }

            headers ||= {}

            tracer.in_span("#{topic} publish", attributes: attributes, kind: :producer) do
              OpenTelemetry.propagation.inject(headers)
              super
            end
          end

          def tracer
            Racecar::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
