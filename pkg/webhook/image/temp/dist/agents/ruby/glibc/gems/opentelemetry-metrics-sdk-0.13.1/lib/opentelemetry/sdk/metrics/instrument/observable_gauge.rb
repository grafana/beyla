# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Instrument
        # {ObservableGauge} is the SDK implementation of {OpenTelemetry::SDK::Metrics::Instrument::AsynchronousInstrument}.
        # Asynchronous Gauge is an asynchronous Instrument which reports non-additive value(s) (e.g. the room temperature)
        class ObservableGauge < OpenTelemetry::SDK::Metrics::Instrument::AsynchronousInstrument
          # Returns the instrument kind as a Symbol
          #
          # @return [Symbol]
          def instrument_kind
            :observable_gauge
          end

          # Observe the Gauge with fixed timeout duration.
          #
          # @param [int] timeout The timeout duration for callback to run, which MUST be a non-negative numeric value.
          # @param [Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>}] attributes
          #   Values must be non-nil and (array of) string, boolean or numeric type.
          #   Array values must not contain nil elements and all elements must be of
          #   the same basic type (string, numeric, boolean).
          def observe(timeout: nil, attributes: {})
            update(timeout, attributes)
          end

          private

          def default_aggregation
            OpenTelemetry::SDK::Metrics::Aggregation::LastValue.new(exemplar_reservoir: @exemplar_reservoir)
          end
        end
      end
    end
  end
end
