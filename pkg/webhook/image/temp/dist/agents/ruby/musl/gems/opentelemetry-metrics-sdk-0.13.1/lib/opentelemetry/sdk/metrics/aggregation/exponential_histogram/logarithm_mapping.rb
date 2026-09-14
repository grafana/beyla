# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        module ExponentialHistogram
          # LogarithmMapping for mapping when scale > 0
          class LogarithmMapping
            attr_reader :scale

            def initialize(scale)
              @scale = scale
              @scale_factor = Log2eScaleFactor::LOG2E_SCALE_BUCKETS[scale] # scale_factor is used for mapping the index
              @min_normal_lower_boundary_index = IEEE754::MIN_NORMAL_EXPONENT << @scale
              @max_normal_lower_boundary_index = ((IEEE754::MAX_NORMAL_EXPONENT + 1) << @scale) - 1
            end

            def map_to_index(value)
              return @min_normal_lower_boundary_index - 1 if value <= IEEE754::MIN_NORMAL_VALUE

              if IEEE754.get_ieee_754_mantissa(value) == 0
                exponent = IEEE754.get_ieee_754_exponent(value)
                return (exponent << @scale) - 1
              end

              [(Math.log(value) * @scale_factor).floor, @max_normal_lower_boundary_index].min
            end

            # for testing
            def get_lower_boundary(inds)
              if inds >= @max_normal_lower_boundary_index
                return 2 * Math.exp((inds - (1 << @scale)) / @scale_factor) if inds == @max_normal_lower_boundary_index

                raise StandardError, 'mapping overflow'
              end

              if inds <= @min_normal_lower_boundary_index
                return IEEE754::MIN_NORMAL_VALUE if inds == @min_normal_lower_boundary_index
                return Math.exp((inds + (1 << @scale)) / @scale_factor) / 2 if inds == @min_normal_lower_boundary_index - 1

                raise StandardError, 'mapping underflow'
              end

              Math.exp(inds / @scale_factor)
            end
          end
        end
      end
    end
  end
end
