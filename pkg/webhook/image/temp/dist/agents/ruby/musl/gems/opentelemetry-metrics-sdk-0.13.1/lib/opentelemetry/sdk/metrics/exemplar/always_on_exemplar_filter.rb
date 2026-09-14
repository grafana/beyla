# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # AlwaysOnExemplarFilter makes all measurements eligible for being an Exemplar.
        class AlwaysOnExemplarFilter < ExemplarFilter
          def self.should_sample?(value, timestamp, attributes, context)
            true
          end
        end
      end
    end
  end
end
