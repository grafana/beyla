# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        # Contains the implementation of the Drop aggregation
        class Drop
          # Use noop reservoir since this is a no-op aggregation
          DEFAULT_RESERVOIR = Metrics::Exemplar::NoopExemplarReservoir.new
          private_constant :DEFAULT_RESERVOIR

          def initialize(exemplar_reservoir: nil)
            @exemplar_reservoir = DEFAULT_RESERVOIR
          end

          def collect(start_time, end_time, data_points)
            data_points.values.map!(&:dup)
          end

          def update(increment, attributes, data_points, exemplar_offer: false)
            data_points[attributes] = NumberDataPoint.new(
              {},
              0,
              0,
              0,
              []
            )
            nil
          end
        end
      end
    end
  end
end
