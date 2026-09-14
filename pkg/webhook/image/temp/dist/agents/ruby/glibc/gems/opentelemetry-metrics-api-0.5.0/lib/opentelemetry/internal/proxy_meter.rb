# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Internal
    # @api private
    #
    # {ProxyMeter} is an implementation of {OpenTelemetry::Trace::Meter}. It is returned from
    # the ProxyMeterProvider until a delegate meter provider is installed. After the delegate
    # meter provider is installed, the ProxyMeter will delegate to the corresponding "real"
    # meter.
    class ProxyMeter < Metrics::Meter
      # Returns a new {ProxyMeter} instance.
      #
      # @return [ProxyMeter]
      def initialize
        super
        @delegate = nil
      end

      # Set the delegate Meter. If this is called more than once, a warning will
      # be logged and superfluous calls will be ignored.
      #
      # @param [Meter] meter The Meter to delegate to
      def delegate=(meter)
        @mutex.synchronize do
          if @delegate.nil?
            @delegate = meter
            @instrument_registry.each_value { |instrument| instrument.upgrade_with(meter) }
          else
            OpenTelemetry.logger.warn 'Attempt to reset delegate in ProxyMeter ignored.'
          end
        end
      end

      private

      def create_instrument(kind, name, unit, description, callback, exemplar_filter, exemplar_reservoir)
        super do
          next ProxyInstrument.new(kind, name, unit, description, callback, exemplar_filter, exemplar_reservoir) if @delegate.nil?

          case kind
          when :counter then @delegate.create_counter(name, unit: unit, description: description, exemplar_filter: exemplar_filter, exemplar_reservoir: exemplar_reservoir)
          when :histogram then @delegate.create_histogram(name, unit: unit, description: description, exemplar_filter: exemplar_filter, exemplar_reservoir: exemplar_reservoir)
          when :up_down_counter then @delegate.create_up_down_counter(name, unit: unit, description: description, exemplar_filter: exemplar_filter, exemplar_reservoir: exemplar_reservoir)
          when :gauge then @delegate.create_gauge(name, unit: unit, description: description, exemplar_filter: exemplar_filter, exemplar_reservoir: exemplar_reservoir)
          when :observable_counter then @delegate.create_observable_counter(name, unit: unit, description: description, exemplar_filter: exemplar_filter, exemplar_reservoir: exemplar_reservoir, callback: callback)
          when :observable_gauge then @delegate.create_observable_gauge(name, unit: unit, description: description, exemplar_filter: exemplar_filter, exemplar_reservoir: exemplar_reservoir, callback: callback)
          when :observable_up_down_counter then @delegate.create_observable_up_down_counter(name, unit: unit, description: description, exemplar_filter: exemplar_filter, exemplar_reservoir: exemplar_reservoir, callback: callback)
          end
        end
      end
    end
  end
end
