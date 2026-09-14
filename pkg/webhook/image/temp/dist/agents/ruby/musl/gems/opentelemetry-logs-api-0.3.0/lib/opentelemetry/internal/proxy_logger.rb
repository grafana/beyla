# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Internal
    # @api private
    #
    # {ProxyLogger} is an implementation of {OpenTelemetry::Logs::Logger}. It is returned from
    # the ProxyLoggerProvider until a delegate logger provider is installed. After the delegate
    # logger provider is installed, the ProxyLogger will delegate to the corresponding "real"
    # logger.
    class ProxyLogger < Logs::Logger
      attr_writer :delegate

      # Returns a new {ProxyLogger} instance.
      #
      # @return [ProxyLogger]
      def initialize
        @delegate = nil
      end

      def on_emit(
        timestamp: nil,
        observed_timestamp: nil,
        severity_number: nil,
        severity_text: nil,
        body: nil,
        trace_id: nil,
        span_id: nil,
        trace_flags: nil,
        attributes: nil,
        context: nil
      )
        unless @delegate.nil?
          return @delegate.on_emit(
            timestamp: nil,
            observed_timestamp: nil,
            severity_number: nil,
            severity_text: nil,
            body: nil,
            trace_id: nil,
            span_id: nil,
            trace_flags: nil,
            attributes: nil,
            context: nil
          )
        end

        super
      end
    end
  end
end
