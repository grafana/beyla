# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Instrument
        # {Counter} is the SDK implementation of {OpenTelemetry::Metrics::Counter}.
        class Counter < OpenTelemetry::SDK::Metrics::Instrument::SynchronousInstrument
          # Returns the instrument kind as a Symbol
          #
          # @return [Symbol]
          def instrument_kind
            :counter
          end

          # Increment the Counter by a fixed amount.
          #
          # @param [numeric] increment The increment amount, which MUST be a non-negative numeric value.
          # @param [Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>}] attributes
          #   Values must be non-nil and (array of) string, boolean or numeric type.
          #   Array values must not contain nil elements and all elements must be of
          #   the same basic type (string, numeric, boolean).
          def add(increment, attributes: {})
            # TODO: When the metrics SDK stabilizes and is merged into the main SDK,
            # we can leverage the SDK Internal validation classes to enforce this:
            # https://github.com/open-telemetry/opentelemetry-ruby/blob/6bec625ef49004f364457c26263df421526b60d6/sdk/lib/opentelemetry/sdk/internal.rb#L47
            if increment.negative?
              OpenTelemetry.logger.warn("#{@name} received a negative value")
            else
              update(increment, attributes)
            end
            nil
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e)
            nil
          end

          private

          def default_aggregation
            OpenTelemetry::SDK::Metrics::Aggregation::Sum.new(exemplar_reservoir: @exemplar_reservoir, monotonic: true)
          end
        end
      end
    end
  end
end
