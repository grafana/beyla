# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    # The Metrics module contains the OpenTelemetry metrics reference
    # implementation.
    module Metrics
      # {Meter} is the SDK implementation of {OpenTelemetry::Metrics::Meter}.
      class Meter < OpenTelemetry::Metrics::Meter
        NAME_REGEX = %r{\A[a-zA-Z][-./\w]{0,254}\z}

        # @api private
        #
        # Returns a new {Meter} instance.
        #
        # @param [String] name Instrumentation package name
        # @param [String] version Instrumentation package version
        #
        # @return [Meter]
        def initialize(name, version, meter_provider)
          @mutex = Mutex.new
          @instrument_registry = {}
          @instrumentation_scope = InstrumentationScope.new(name, version)
          @meter_provider = meter_provider
        end

        # Multiple-instrument callbacks
        # Callbacks registered after the time of instrument creation MAY be associated with multiple instruments.
        # Related spec: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/api.md#multiple-instrument-callbacks
        # Related spec: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/api.md#synchronous-instrument-api
        #
        # @param [Array] instruments A list (or tuple, etc.) of Instruments used in the callback function.
        # @param [Proc] callback A callback function
        #
        # It is RECOMMENDED that the API authors use one of the following forms for the callback function:
        # The list (or tuple, etc.) returned by the callback function contains (Instrument, Measurement) pairs.
        # the Observable Result parameter receives an additional (Instrument, Measurement) pairs
        # Here it chose the second form
        def register_callback(instruments, callback)
          instruments.each do |instrument|
            instrument.register_callback(callback)
          end
        end

        def unregister(instruments, callback)
          instruments.each do |instrument|
            instrument.unregister(callback)
          end
        end

        # @api private
        def add_metric_reader(metric_reader)
          @instrument_registry.each_value do |instrument|
            instrument.register_with_new_metric_store(metric_reader.metric_store)
          end
        end

        def create_instrument(kind, name, unit, description, callback, exemplar_filter, exemplar_reservoir)
          raise InstrumentNameError if name.nil?
          raise InstrumentNameError if name.empty?
          raise InstrumentNameError unless NAME_REGEX.match?(name)
          raise InstrumentUnitError if unit && (!unit.ascii_only? || unit.size > 63)
          raise InstrumentDescriptionError if description && (description.size > 1023 || !utf8mb3_encoding?(description.dup))

          super do
            case kind
            when :counter then OpenTelemetry::SDK::Metrics::Instrument::Counter.new(name, unit, description, @instrumentation_scope, @meter_provider, exemplar_filter, exemplar_reservoir)
            when :observable_counter then OpenTelemetry::SDK::Metrics::Instrument::ObservableCounter.new(name, unit, description, callback, @instrumentation_scope, @meter_provider, exemplar_filter, exemplar_reservoir)
            when :gauge then OpenTelemetry::SDK::Metrics::Instrument::Gauge.new(name, unit, description, @instrumentation_scope, @meter_provider, exemplar_filter, exemplar_reservoir)
            when :histogram then OpenTelemetry::SDK::Metrics::Instrument::Histogram.new(name, unit, description, @instrumentation_scope, @meter_provider, exemplar_filter, exemplar_reservoir)
            when :observable_gauge then OpenTelemetry::SDK::Metrics::Instrument::ObservableGauge.new(name, unit, description, callback, @instrumentation_scope, @meter_provider, exemplar_filter, exemplar_reservoir)
            when :up_down_counter then OpenTelemetry::SDK::Metrics::Instrument::UpDownCounter.new(name, unit, description, @instrumentation_scope, @meter_provider, exemplar_filter, exemplar_reservoir)
            when :observable_up_down_counter then OpenTelemetry::SDK::Metrics::Instrument::ObservableUpDownCounter.new(name, unit, description, callback, @instrumentation_scope, @meter_provider, exemplar_filter, exemplar_reservoir)
            end
          end
        end

        def utf8mb3_encoding?(string)
          string.force_encoding('UTF-8').valid_encoding? &&
            string.each_char { |c| return false if c.bytesize >= 4 }
        end
      end
    end
  end
end
