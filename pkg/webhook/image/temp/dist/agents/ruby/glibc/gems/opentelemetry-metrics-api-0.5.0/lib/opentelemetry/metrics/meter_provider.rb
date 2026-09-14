# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Metrics
    # No-op implementation of a meter provider.
    class MeterProvider
      # Returns a {Meter} instance.
      #
      # @param [String] name Instrumentation package name
      # @param [optional String] version Instrumentation package version
      #
      # @return [Meter]
      def meter(name, version: nil)
        @meter ||= Meter.new
      end
    end
  end
end
