# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry/metrics'
require 'opentelemetry/metrics/version'
require 'opentelemetry/internal/proxy_instrument'
require 'opentelemetry/internal/proxy_meter_provider'
require 'opentelemetry/internal/proxy_meter'

# OpenTelemetry is an open source observability framework, providing a
# general-purpose API, SDK, and related tools required for the instrumentation
# of cloud-native software, frameworks, and libraries.
#
# The OpenTelemetry module provides global accessors for telemetry objects.
module OpenTelemetry
  @meter_provider = Internal::ProxyMeterProvider.new

  # Register the global meter provider.
  #
  # @param [MeterProvider] provider A meter provider to register as the
  #   global instance.
  def meter_provider=(provider)
    @mutex.synchronize do
      if @meter_provider.instance_of? Internal::ProxyMeterProvider
        logger.debug("Upgrading default proxy meter provider to #{provider.class}")
        @meter_provider.delegate = provider
      end
      @meter_provider = provider
    end
  end

  # @return [Object, Metrics::MeterProvider] registered meter provider or a
  #   default no-op implementation of the meter provider.
  def meter_provider
    @mutex.synchronize { @meter_provider }
  end
end
