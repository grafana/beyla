# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Export
        # Outputs {MetricData} to the console
        #
        # Potentially useful for exploratory purposes.
        class ConsoleMetricPullExporter < MetricReader
          def initialize
            super
            @stopped = false
          end

          def pull
            export(collect)
          end

          def export(metrics, timeout: nil)
            return FAILURE if @stopped

            Array(metrics).each { |metric| pp metric }

            SUCCESS
          end

          def force_flush(timeout: nil)
            SUCCESS
          end

          def shutdown(timeout: nil)
            @stopped = true
            SUCCESS
          end
        end
      end
    end
  end
end
