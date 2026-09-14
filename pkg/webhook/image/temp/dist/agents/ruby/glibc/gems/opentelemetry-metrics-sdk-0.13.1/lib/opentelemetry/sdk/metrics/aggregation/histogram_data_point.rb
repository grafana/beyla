# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        # TODO: Deal with this later
        # rubocop:disable Lint/StructNewOverride
        HistogramDataPoint = Struct.new(:attributes,            # optional Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>}
                                        :start_time_unix_nano,  # Integer nanoseconds since Epoch
                                        :time_unix_nano,        # Integer nanoseconds since Epoch
                                        :count,                 # Integer count is the number of values in the population. Must be non-negative.
                                        :sum,                   # Float sum of the values in the population. If count is zero then this field must be zero.
                                        :bucket_counts,         # optional Array[Integer] field contains the count values of histogram for each bucket.
                                        :explicit_bounds,       # Array[Float] specifies buckets with explicitly defined bounds for values.
                                        :exemplars,             # optional List of exemplars collected from measurements that were used to form the data point
                                        :min,                   # optional Float min is the minimum value over (start_time, end_time].
                                        :max)                   # optional Float max is the maximum value over (start_time, end_time].
        # rubocop:enable Lint/StructNewOverride
      end
    end
  end
end
