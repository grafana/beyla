# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Internal
    # @api private
    #
    # {ProxyMeterProvider} is an implementation of {OpenTelemetry::Metrics::MeterProvider}.
    # It is the default global Meter provider returned by OpenTelemetry.meter_provider.
    # It delegates to a "real" MeterProvider after the global meter provider is registered.
    # It returns {ProxyMeter} instances until the delegate is installed.
    class ProxyMeterProvider < Metrics::MeterProvider
      Key = Struct.new(:name, :version)
      private_constant(:Key)

      # Returns a new {ProxyMeterProvider} instance.
      #
      # @return [ProxyMeterProvider]
      def initialize
        @mutex = Mutex.new
        @registry = {}
        @delegate = nil
      end

      # Set the delegate Meter provider. If this is called more than once, a warning will
      # be logged and superfluous calls will be ignored.
      #
      # @param [MeterProvider] provider The Meter provider to delegate to
      def delegate=(provider)
        unless @delegate.nil?
          OpenTelemetry.logger.warn 'Attempt to reset delegate in ProxyMeterProvider ignored.'
          return
        end

        @mutex.synchronize do
          @delegate = provider
          @registry.each { |key, meter| meter.delegate = provider.meter(key.name, version: key.version) }
        end
      end

      # Returns a {Meter} instance.
      #
      # @param [optional String] name Instrumentation package name
      # @param [optional String] version Instrumentation package version
      #
      # @return [Meter]
      def meter(name = nil, version: nil)
        @mutex.synchronize do
          return @delegate.meter(name, version: version) unless @delegate.nil?

          @registry[Key.new(name, version)] ||= ProxyMeter.new
        end
      end
    end
  end
end
