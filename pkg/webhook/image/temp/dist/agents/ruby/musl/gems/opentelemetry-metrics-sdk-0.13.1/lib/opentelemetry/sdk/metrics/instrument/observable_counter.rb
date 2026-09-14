# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Instrument
        # {ObservableCounter} is the SDK implementation of {OpenTelemetry::SDK::Metrics::Instrument::AsynchronousInstrument}.
        # Asynchronous Counter is an asynchronous Instrument which reports monotonically increasing value(s) when the instrument is being observed.
        class ObservableCounter < OpenTelemetry::SDK::Metrics::Instrument::AsynchronousInstrument
          # Returns the instrument kind as a Symbol
          #
          # @return [Symbol]
          def instrument_kind
            :observable_counter
          end

          # Observe the ObservableCounter with fixed timeout duration.
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
            OpenTelemetry::SDK::Metrics::Aggregation::Sum.new(exemplar_reservoir: @exemplar_reservoir, monotonic: true, instrument_kind: instrument_kind)
          end
        end
      end
    end
  end
end
