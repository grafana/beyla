# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module State
        # @api private
        #
        # The AsynchronousMetricStream class provides SDK internal functionality that is not a part of the
        # public API. It extends MetricStream to support asynchronous instruments.
        class AsynchronousMetricStream < MetricStream
          DEFAULT_TIMEOUT = 30

          def initialize(
            name,
            description,
            unit,
            instrument_kind,
            meter_provider,
            instrumentation_scope,
            aggregation,
            callback,
            timeout,
            attributes,
            exemplar_filter,
            exemplar_reservoir
          )
            # Call parent constructor with common parameters
            super(name, description, unit, instrument_kind, meter_provider, instrumentation_scope, aggregation, exemplar_filter, exemplar_reservoir)

            # Initialize asynchronous-specific attributes
            @callback = callback
            @start_time = OpenTelemetry::Common::Utilities.time_in_nanoseconds
            @timeout = timeout
            @attributes = attributes
          end

          # When collect, if there are asynchronous SDK Instruments involved, their callback functions will be triggered.
          # Related spec: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/sdk.md#collect
          # invoke_callback will update the data_points in aggregation
          def collect(start_time, end_time)
            invoke_callback(@timeout, @attributes)

            # Call parent collect method for the core collection logic
            super(start_time, end_time)
          end

          def invoke_callback(timeout, attributes)
            if @registered_views.empty?
              @mutex.synchronize do
                @callback.each do |cb|
                  value = safe_guard_callback(cb, timeout: timeout)
                  if value.is_a?(Numeric)
                    exemplar_offer = should_offer_exemplar?(value, attributes)
                    @default_aggregation.update(value, attributes, @data_points, exemplar_offer: exemplar_offer)
                  end
                end
              end
            else
              @registered_views.each do |view, data_points|
                @mutex.synchronize do
                  @callback.each do |cb|
                    value = safe_guard_callback(cb, timeout: timeout)
                    next unless value.is_a?(Numeric) # ignore if value is not valid number

                    merged_attributes = attributes || {}
                    merged_attributes.merge!(view.attribute_keys)
                    if view.valid_aggregation?
                      exemplar_offer = should_offer_exemplar?(value, merged_attributes)
                      view.aggregation.update(value, attributes, data_points, exemplar_offer: exemplar_offer)
                    end
                  end
                end
              end
            end
          end

          private

          def safe_guard_callback(callback, timeout: DEFAULT_TIMEOUT)
            result = nil
            thread = Thread.new do
              result = callback.call
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e, message: 'Error invoking callback.')
              result = :error
            end

            unless thread.join(timeout)
              thread.kill
              OpenTelemetry.handle_error(message: "Timeout while invoking callback after #{timeout} seconds")
              return nil
            end

            result == :error ? nil : result
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e, message: 'Unexpected error in callback execution.')
            nil
          end
        end
      end
    end
  end
end
