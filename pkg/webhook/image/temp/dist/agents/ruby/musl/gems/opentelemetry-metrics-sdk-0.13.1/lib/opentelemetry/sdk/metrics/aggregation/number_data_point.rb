# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        NumberDataPoint = Struct.new(:attributes,            # Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>}
                                     :start_time_unix_nano,  # Integer nanoseconds since Epoch
                                     :time_unix_nano,        # Integer nanoseconds since Epoch
                                     :value,                 # Numeric
                                     :exemplars)             # optional List of exemplars collected from measurements that were used to form the data point
      end
    end
  end
end
