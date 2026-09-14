# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        module ExponentialHistogram
          # Log2eScaleFactor is precomputed scale factor value
          class Log2eScaleFactor
            MAX_SCALE = 20

            LOG2E_SCALE_BUCKETS = (0..MAX_SCALE).map do |scale|
              log2e = 1 / Math.log(2)
              Math.ldexp(log2e, scale)
            end

            # for testing
            def self.log2e_scale_buckets
              LOG2E_SCALE_BUCKETS
            end
          end
        end
      end
    end
  end
end
