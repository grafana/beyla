# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # NoopExemplarReservoir
        class NoopExemplarReservoir < ExemplarReservoir
          def offer(value: nil, timestamp: nil, attributes: nil, context: nil); end

          def collect(attributes: nil, aggregation_temporality: :delta)
            []
          end
        end
      end
    end
  end
end
