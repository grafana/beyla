# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Logs
      # LogRecordProcessor describes a duck type and provides a synchronous no-op hook for when a
      # {LogRecord} is emitted. It is not required to subclass this
      # class to provide an implementation of LogRecordProcessor, provided the interface is
      # satisfied.
      class LogRecordProcessor
        # Called when a {LogRecord} is emitted. Subsequent calls are not
        # permitted after shutdown is called.
        # @param [LogRecord] log_record The emitted {LogRecord}
        # @param [Context] context The {Context}
        def on_emit(log_record, context); end

        # Export all log records to the configured `Exporter` that have not yet
        # been exported.
        #
        # This method should only be called in cases where it is absolutely
        # necessary, such as when using some FaaS providers that may suspend
        # the process after an invocation, but before the `Processor` exports
        # the completed spans.
        #
        # @param [optional Numeric] timeout An optional timeout in seconds.
        # @return [Integer] Export::SUCCESS if no error occurred, Export::FAILURE if
        #   a non-specific failure occurred, Export::TIMEOUT if a timeout occurred.
        def force_flush(timeout: nil)
          Export::SUCCESS
        end

        # Called when {LoggerProvider#shutdown} is called.
        #
        # @param [optional Numeric] timeout An optional timeout in seconds.
        # @return [Integer] Export::SUCCESS if no error occurred, Export::FAILURE if
        #   a non-specific failure occurred, Export::TIMEOUT if a timeout occurred.
        def shutdown(timeout: nil)
          Export::SUCCESS
        end
      end
    end
  end
end
