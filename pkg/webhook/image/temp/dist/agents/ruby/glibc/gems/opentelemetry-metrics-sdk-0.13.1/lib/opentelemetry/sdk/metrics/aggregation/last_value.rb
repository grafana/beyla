# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        # Contains the implementation of the LastValue aggregation
        class LastValue
          attr_reader :exemplar_reservoir

          # if no reservoir pass from instrument, then use this empty reservoir to avoid no method found error
          DEFAULT_RESERVOIR = Metrics::Exemplar::SimpleFixedSizeExemplarReservoir.new
          private_constant :DEFAULT_RESERVOIR

          def initialize(exemplar_reservoir: nil)
            @exemplar_reservoir = exemplar_reservoir || DEFAULT_RESERVOIR
            @exemplar_reservoir_storage = {}
          end

          def collect(start_time, end_time, data_points)
            ndps = data_points.values.map! do |ndp|
              ndp.start_time_unix_nano = start_time
              ndp.time_unix_nano = end_time
              reservoir = @exemplar_reservoir_storage[ndp.attributes]
              ndp.exemplars = reservoir&.collect(attributes: ndp.attributes, aggregation_temporality: :delta)
              ndp
            end
            data_points.clear
            ndps
          end

          def update(increment, attributes, data_points, exemplar_offer: false)
            reservoir = @exemplar_reservoir_storage[attributes]
            unless reservoir
              reservoir = @exemplar_reservoir.dup
              reservoir.reset
              @exemplar_reservoir_storage[attributes] = reservoir
            end

            if exemplar_offer
              reservoir.offer(value: increment,
                              timestamp: OpenTelemetry::Common::Utilities.time_in_nanoseconds,
                              attributes: attributes,
                              context: OpenTelemetry::Context.current)
            end

            data_points[attributes] = NumberDataPoint.new(
              attributes,
              nil,
              nil,
              increment,
              nil
            )
            nil
          end
        end
      end
    end
  end
end
