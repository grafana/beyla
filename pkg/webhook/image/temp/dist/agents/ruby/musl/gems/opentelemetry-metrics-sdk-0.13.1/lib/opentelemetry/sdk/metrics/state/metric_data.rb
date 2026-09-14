# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module State
        # MetricData is a Struct containing {MetricStream} data for export.
        MetricData = Struct.new(:name,                      # String
                                :description,               # String
                                :unit,                      # String
                                :instrument_kind,           # Symbol
                                :resource,                  # OpenTelemetry::SDK::Resources::Resource
                                :instrumentation_scope,     # OpenTelemetry::SDK::InstrumentationScope
                                :data_points,               # Hash{Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>} => Numeric}
                                :aggregation_temporality,   # Symbol
                                :start_time_unix_nano,      # Integer nanoseconds since Epoch
                                :time_unix_nano,            # Integer nanoseconds since Epoch
                                :is_monotonic)              # Boolean
      end
    end
  end
end
