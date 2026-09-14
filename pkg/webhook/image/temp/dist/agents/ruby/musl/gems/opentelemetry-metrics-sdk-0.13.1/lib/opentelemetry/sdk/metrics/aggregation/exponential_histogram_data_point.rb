# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        # rubocop:disable Lint/StructNewOverride

        ExponentialHistogramDataPoint = Struct.new(:attributes, # optional Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>}
                                                   :start_time_unix_nano,   # Integer nanoseconds since Epoch
                                                   :time_unix_nano,         # Integer nanoseconds since Epoch
                                                   :count,                  # Integer count is the number of values in the population. Must be non-negative
                                                   :sum,                    # Integer sum of the values in the population. If count is zero then this field then this field must be zero
                                                   :scale,                  # Integer scale factor
                                                   :zero_count,             # Integer special bucket that count of observations that fall into the zero bucket
                                                   :positive,               # Buckets representing the positive range of the histogram.
                                                   :negative,               # Buckets representing the negative range of the histogram.
                                                   :flags,                  # Integer flags associated with the data point.
                                                   :exemplars,              # optional List of exemplars collected from measurements that were used to form the data point
                                                   :min,                    # optional Float min is the minimum value over (start_time, end_time].
                                                   :max,                    # optional Float max is the maximum value over (start_time, end_time].
                                                   :zero_threshold)         # optional Float the threshold for the zero bucket
        # rubocop:enable Lint/StructNewOverride
      end
    end
  end
end
