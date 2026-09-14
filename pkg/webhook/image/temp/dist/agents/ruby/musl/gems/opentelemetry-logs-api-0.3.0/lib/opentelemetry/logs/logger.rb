# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Logs
    # No-op implementation of logger.
    class Logger
      # rubocop:disable Style/EmptyMethod

      # Emit a {LogRecord} to the processing pipeline.
      #
      # @param timestamp [optional Time] Time when the event occurred.
      # @param observed_timestamp [optional Time] Time when the event was
      #   observed by the collection system.
      # @param context [optional Context] The Context to associate with the
      #   LogRecord. Intended default: OpenTelemetry::Context.current
      # @param severity_number [optional Integer] Numerical value of the
      #   severity. Smaller numerical values correspond to less severe events
      #   (such as debug events), larger numerical values correspond to more
      #   severe events (such as errors and critical events).
      # @param [optional String] severity_text Original string representation of
      #   the severity as it is known at the source. Also known as log level.
      # @param [optional String, Numeric, Boolean, Array<String, Numeric,
      #   Boolean>, Hash{String => String, Numeric, Boolean, Array<String,
      #   Numeric, Boolean>}] body A value containing the body of the log record.
      # @param [optional String] trace_id The trace ID associated with the
      #   current context.
      # @param [optional String] span_id The span ID associated with the
      #   current context.
      # @param [optional TraceFlags] trace_flags The trace flags associated
      #   with the current context.
      # @param [optional Hash{String => String, Numeric, Boolean,
      #   Array<String, Numeric, Boolean>}] attributes Additional information
      #   about the event.
      # @param [optional Context] context The Context to associate with the
      #   LogRecord. Intended default: OpenTelemetry::Context.current
      #
      # @api public
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
      end
      # rubocop:enable Style/EmptyMethod
    end
  end
end
