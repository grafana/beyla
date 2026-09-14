# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Logs
      # The SDK implementation of OpenTelemetry::Logs::Logger
      class Logger < OpenTelemetry::Logs::Logger
        # @api private
        #
        # Returns a new {OpenTelemetry::SDK::Logs::Logger} instance. This should
        # not be called directly. New loggers should be created using
        # {LoggerProvider#logger}.
        #
        # @param [String] name Instrumentation package name
        # @param [String] version Instrumentation package version
        # @param [LoggerProvider] logger_provider The {LoggerProvider} that
        #   initialized the logger
        #
        # @return [OpenTelemetry::SDK::Logs::Logger]
        def initialize(name, version, logger_provider)
          @instrumentation_scope = InstrumentationScope.new(name, version)
          @logger_provider = logger_provider
        end

        # Emit a {LogRecord} to the processing pipeline.
        #
        # @param [optional Time] timestamp Time when the event occurred.
        # @param [optional Time] observed_timestamp Time when the event was
        #   observed by the collection system.
        # @param [optional OpenTelemetry::Trace::SpanContext] span_context The
        #   OpenTelemetry::Trace::SpanContext to associate with the
        #   {LogRecord}.
        # @param [optional String] severity_text Original string representation of
        #   the severity as it is known at the source. Also known as log level.
        # @param severity_number [optional Integer] Numerical value of the
        #   severity. Smaller numerical values correspond to less severe events
        #   (such as debug events), larger numerical values correspond to more
        #   severe events (such as errors and critical events).
        # @param [optional String, Numeric, Boolean, Array<String, Numeric,
        #   Boolean>, Hash{String => String, Numeric, Boolean, Array<String,
        #   Numeric, Boolean>}] body A value containing the body of the log record.
        # @param [optional Hash{String => String, Numeric, Boolean,
        #   Array<String, Numeric, Boolean>}] attributes Additional information
        #   about the event.
        # @param [optional String (16-byte binary)] trace_id Request trace id as
        #   defined in {https://www.w3.org/TR/trace-context/#trace-id W3C Trace Context}.
        #   Can be set for logs that are part of request processing and have an
        #   assigned trace id.
        # @param [optional String (8-byte binary)] span_id Span id. Can be set
        #   for logs that are part of a particular processing span. If span_id
        #   is present trace_id should also be present.
        # @param [optional Integer (8-bit byte of bit flags)] trace_flags Trace
        #   flag as defined in {https://www.w3.org/TR/trace-context/#trace-flags W3C Trace Context}
        #   specification. At the time of writing the specification defines one
        #   flag - the SAMPLED flag.
        # @param [optional OpenTelemetry::Context] context The OpenTelemetry::Context
        #   to associate with the {LogRecord}.
        #
        # @api public
        def on_emit(timestamp: nil,
                    observed_timestamp: Time.now,
                    severity_text: nil,
                    severity_number: nil,
                    body: nil,
                    attributes: nil,
                    trace_id: nil,
                    span_id: nil,
                    trace_flags: nil,
                    context: OpenTelemetry::Context.current)
          current_span = OpenTelemetry::Trace.current_span(context)
          span_context = current_span.context unless current_span == OpenTelemetry::Trace::Span::INVALID

          @logger_provider.on_emit(timestamp: timestamp,
                                   observed_timestamp: observed_timestamp,
                                   severity_text: severity_text,
                                   severity_number: severity_number,
                                   body: body,
                                   attributes: attributes,
                                   trace_id: trace_id || span_context&.trace_id,
                                   span_id: span_id || span_context&.span_id,
                                   trace_flags: trace_flags || span_context&.trace_flags,
                                   instrumentation_scope: @instrumentation_scope,
                                   context: context)
        end
      end
    end
  end
end
