# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module State
        # @api private
        #
        # The MetricStore module provides SDK internal functionality that is not a part of the
        # public API.
        class MetricStore
          def initialize
            @mutex = Mutex.new
            @epoch_start_time = OpenTelemetry::Common::Utilities.time_in_nanoseconds
            @epoch_end_time = nil
            @metric_streams = []
          end

          def collect
            @mutex.synchronize do
              @epoch_end_time = OpenTelemetry::Common::Utilities.time_in_nanoseconds
              snapshot = @metric_streams.flat_map { |ms| ms.collect(@epoch_start_time, @epoch_end_time) }
              @epoch_start_time = @epoch_end_time

              snapshot
            end
          end

          def add_metric_stream(metric_stream)
            @mutex.synchronize do
              @metric_streams = @metric_streams.dup.push(metric_stream)
              nil
            end
          end
        end
      end
    end
  end
end
