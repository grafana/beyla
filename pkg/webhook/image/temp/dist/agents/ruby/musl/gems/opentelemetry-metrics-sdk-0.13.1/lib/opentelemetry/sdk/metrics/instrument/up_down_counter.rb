# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Instrument
        # {UpDownCounter} is the SDK implementation of {OpenTelemetry::Metrics::UpDownCounter}.
        class UpDownCounter < OpenTelemetry::SDK::Metrics::Instrument::SynchronousInstrument
          # Returns the instrument kind as a Symbol
          #
          # @return [Symbol]
          def instrument_kind
            :up_down_counter
          end

          # Increment or decrement the UpDownCounter by a fixed amount.
          #
          # @param [Numeric] amount The amount to be added, can be positive, negative or zero.
          # @param [Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>}] attributes
          #   Values must be non-nil and (array of) string, boolean or numeric type.
          #   Array values must not contain nil elements and all elements must be of
          #   the same basic type (string, numeric, boolean).
          def add(amount, attributes: {})
            update(amount, attributes)
            nil
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e)
            nil
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
