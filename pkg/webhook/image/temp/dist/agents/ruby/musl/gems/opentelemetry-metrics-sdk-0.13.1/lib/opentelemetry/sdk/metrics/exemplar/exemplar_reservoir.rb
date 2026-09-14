# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # ExemplarReservoir base class
        # Subclasses must implement offer and collect methods
        class ExemplarReservoir
          # Store the info into exemplars bucket
          #
          # @param [Numeric] value Value of the measurement
          # @param [Integer] timestamp Time of recording in nanoseconds
          # @param [Hash] attributes Complete set of Attributes of the measurement
          # @param [Context] context SpanContext of the measurement, which covers the Baggage and the current active Span.
          #
          # @return [Nil]
          def offer(value: nil, timestamp: nil, attributes: nil, context: nil)
            raise NotImplementedError, "#{self.class} must implement #offer"
          end

          # Return list of Exemplars based on given attributes
          #
          # @param [Hash] attributes Value of the measurement
          # @param [Symbol] aggregation_temporality Should remove the original exemplars or not, default delta
          #
          # @return [Array] exemplars Array of exemplars
          def collect(attributes: nil, aggregation_temporality: :delta)
            raise NotImplementedError, "#{self.class} must implement #collect"
          end
        end
      end
    end
  end
end
