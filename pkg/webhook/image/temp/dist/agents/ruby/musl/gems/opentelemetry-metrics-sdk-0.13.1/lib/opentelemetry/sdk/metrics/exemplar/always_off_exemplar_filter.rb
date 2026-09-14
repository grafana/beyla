# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # AlwaysOffExemplarFilter makes no measurements eligible for being an Exemplar.
        # Using this ExemplarFilter is as good as disabling Exemplar feature.
        class AlwaysOffExemplarFilter < ExemplarFilter
          def self.should_sample?(value, timestamp, attributes, context)
            false
          end
        end
      end
    end
  end
end
