# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        module ExponentialHistogram
          # IEEE754 standard for floating-point calculation
          module IEEE754
            MANTISSA_WIDTH = 52
            EXPONENT_WIDTH = 11

            MANTISSA_MASK = (1 << MANTISSA_WIDTH) - 1
            EXPONENT_BIAS = (2**(EXPONENT_WIDTH - 1)) - 1
            EXPONENT_MASK = ((1 << EXPONENT_WIDTH) - 1) << MANTISSA_WIDTH
            SIGN_MASK = 1 << (EXPONENT_WIDTH + MANTISSA_WIDTH)

            MIN_NORMAL_EXPONENT = -EXPONENT_BIAS + 1
            MAX_NORMAL_EXPONENT = EXPONENT_BIAS

            MIN_NORMAL_VALUE = Float::MIN
            MAX_NORMAL_VALUE = Float::MAX

            def self.get_ieee_754_exponent(value)
              bits = [value].pack('d').unpack1('Q')
              ((bits & EXPONENT_MASK) >> MANTISSA_WIDTH) - EXPONENT_BIAS
            end

            def self.get_ieee_754_mantissa(value)
              bits = [value].pack('d').unpack1('Q')
              bits & MANTISSA_MASK
            end
          end
        end
      end
    end
  end
end
