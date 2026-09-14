# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Bunny
      module Patches
        # The Consumer module contains the instrumentation patch for the Consumer class
        module Consumer
          def call(delivery_info, properties, payload)
            OpenTelemetry::Instrumentation::Bunny::PatchHelpers.with_process_span(queue.channel, tracer, delivery_info, properties) do
              super
            end
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
