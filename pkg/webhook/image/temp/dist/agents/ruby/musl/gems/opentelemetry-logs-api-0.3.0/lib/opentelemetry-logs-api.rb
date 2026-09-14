# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry/logs'
require 'opentelemetry/logs/version'
require 'opentelemetry/internal/proxy_logger_provider'
require 'opentelemetry/internal/proxy_logger'

# OpenTelemetry is an open source observability framework, providing a
# general-purpose API, SDK, and related tools required for the instrumentation
# of cloud-native software, frameworks, and libraries.
#
# The OpenTelemetry module in the Logs API gem provides global accessors
# for logs-related objects.
module OpenTelemetry
  @logger_provider = Internal::ProxyLoggerProvider.new

  # Register the global logger provider.
  #
  # @param [LoggerProvider] provider A logger provider to register as the
  #   global instance.
  def logger_provider=(provider)
    @mutex.synchronize do
      if @logger_provider.instance_of? Internal::ProxyLoggerProvider
        logger.debug("Upgrading default proxy logger provider to #{provider.class}")
        @logger_provider.delegate = provider
      end
      @logger_provider = provider
    end
  end

  # @return [Object, Logs::LoggerProvider] registered logger provider or a
  #   default no-op implementation of the logger provider.
  def logger_provider
    @mutex.synchronize { @logger_provider }
  end
end
