# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # ExemplarFilter determines which measurements are eligible for becoming an Exemplar. Available Filters include: AlwaysOn, AlwaysOff, and TraceBased.
        class ExemplarFilter
          # Returns a {Boolean} value.
          #
          # @param [Integer] value Value of the measurement
          # @param [Hash] attributes Complete set of Attributes of the measurement
          # @param [Context] context Context of the measurement, which covers the Baggage and the current active Span.
          #
          # @return [Boolean]
          def self.should_sample?(value, attributes, context); end
        end
      end
    end
  end
end
