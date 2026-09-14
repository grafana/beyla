# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Internal
    # @api private
    #
    # {ProxyLoggerProvider} is an implementation of {OpenTelemetry::Logs::LoggerProvider}.
    # It is the default global logger provider returned by OpenTelemetry.logger_provider.
    # It delegates to a "real" LoggerProvider after the global logger provider is registered.
    # It returns {ProxyLogger} instances until the delegate is installed.
    class ProxyLoggerProvider < Logs::LoggerProvider
      Key = Struct.new(:name, :version)
      private_constant(:Key)
      # Returns a new {ProxyLoggerProvider} instance.
      #
      # @return [ProxyLoggerProvider]
      def initialize
        super

        @mutex = Mutex.new
        @registry = {}
        @delegate = nil
      end

      # Set the delegate logger provider. If this is called more than once, a warning will
      # be logged and superfluous calls will be ignored.
      #
      # @param [LoggerProvider] provider The logger provider to delegate to
      def delegate=(provider)
        unless @delegate.nil?
          OpenTelemetry.logger.warn 'Attempt to reset delegate in ProxyLoggerProvider ignored.'
          return
        end

        @mutex.synchronize do
          @delegate = provider
          @registry.each { |key, logger| logger.delegate = provider.logger(key.name, key.version) }
        end
      end

      # Returns a {Logger} instance.
      #
      # @param [optional String] name Instrumentation package name
      # @param [optional String] version Instrumentation package version
      #
      # @return [Logger]
      def logger(name = nil, version = nil)
        @mutex.synchronize do
          return @delegate.logger(name, version) unless @delegate.nil?

          @registry[Key.new(name, version)] ||= ProxyLogger.new
        end
      end
    end
  end
end
