# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Instrument
        # {ObservableUpDownCounter} is the SDK implementation of {OpenTelemetry::SDK::Metrics::Instrument::AsynchronousInstrument}.
        # Asynchronous UpDownCounter is an asynchronous Instrument which reports additive value(s) (e.g. the process heap size)
        class ObservableUpDownCounter < OpenTelemetry::SDK::Metrics::Instrument::AsynchronousInstrument
          # Returns the instrument kind as a Symbol
          #
          # @return [Symbol]
          def instrument_kind
            :observable_up_down_counter
          end

          # Observe the UpDownCounter with fixed timeout duration.
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
            OpenTelemetry::SDK::Metrics::Aggregation::Sum.new(aggregation_temporality: :cumulative, exemplar_reservoir: @exemplar_reservoir, monotonic: false)
          end
        end
      end
    end
  end
end
