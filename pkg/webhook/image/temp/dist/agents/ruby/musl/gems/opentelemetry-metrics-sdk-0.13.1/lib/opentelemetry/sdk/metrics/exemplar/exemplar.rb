# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # Exemplar is a Struct containing Exemplar data for export.

        Exemplar = Struct.new(
          :filtered_attributes,  # Hash - attributes filtered from point attributes
          :value,                # Numeric - measured value
          :time_unix_nano,       # Integer - measurement timestamp in nanoseconds
          :span_id,              # String - hex span ID
          :trace_id              # String - hex trace ID
        )
      end
    end
  end
end
