# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        module ExponentialHistogram
          # LogarithmMapping for mapping when scale < 0
          class ExponentMapping
            attr_reader :scale

            def initialize(scale)
              @scale = scale
              @min_normal_lower_boundary_index = calculate_min_normal_lower_boundary_index(scale)
              @max_normal_lower_boundary_index = IEEE754::MAX_NORMAL_EXPONENT >> -@scale
            end

            def map_to_index(value)
              return @min_normal_lower_boundary_index if value < IEEE754::MIN_NORMAL_VALUE

              exponent = IEEE754.get_ieee_754_exponent(value)
              correction = (IEEE754.get_ieee_754_mantissa(value) - 1) >> IEEE754::MANTISSA_WIDTH
              (exponent + correction) >> -@scale
            end

            def calculate_min_normal_lower_boundary_index(scale)
              inds = IEEE754::MIN_NORMAL_EXPONENT >> -scale
              inds -= 1 if -scale < 2
              inds
            end

            # for testing
            def get_lower_boundary(inds)
              raise StandardError, 'mapping underflow' if inds < @min_normal_lower_boundary_index || inds > @max_normal_lower_boundary_index

              Math.ldexp(1, inds << -@scale)
            end
          end
        end
      end
    end
  end
end
