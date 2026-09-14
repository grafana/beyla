# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Logs
      module Export
        # An implementation of {LogRecordProcessor} that converts the LogRecord
        # into a ReadableLogRecord and passes it to the configured exporter
        # on emit.
        #
        # Typically, the SimpleLogRecordProcessor will be most suitable for use
        # in testing; it should be used with caution in production. It may be
        # appropriate for production use in scenarios where creating multiple
        # threads is not desirable as well as scenarios where different custom
        # attributes should be added to individual log records based on code
        # scopes.
        class SimpleLogRecordProcessor < OpenTelemetry::SDK::Logs::LogRecordProcessor
          # Returns a new {SimpleLogRecordProcessor} that converts log records
          # to {ReadableLogRecords} and forwards them to the given
          # log_record_exporter.
          #
          # @param log_record_exporter the LogRecordExporter to push the
          #   recorded log records.
          # @return [SimpleLogRecordProcessor]
          # @raise ArgumentError if the log_record_exporter is invalid or nil.
          def initialize(log_record_exporter)
            raise ArgumentError, "exporter #{log_record_exporter.inspect} does not appear to be a valid exporter" unless Common::Utilities.valid_exporter?(log_record_exporter)

            @log_record_exporter = log_record_exporter
            @stopped = false
          end

          # Called when a LogRecord is emitted.
          #
          # This method is called synchronously on the execution thread. It
          # should not throw or block the execution thread. It may not be called
          # after shutdown.
          #
          # @param [LogRecord] log_record The emitted {LogRecord}
          # @param [Context] _context The current {Context}
          def on_emit(log_record, _context)
            return if @stopped

            @log_record_exporter&.export([log_record.to_log_record_data])
          rescue => e # rubocop:disable Style/RescueStandardError
            OpenTelemetry.handle_error(exception: e, message: 'Unexpected error in Logger#on_emit')
          end

          # Export all log records to the configured `Exporter` that have not
          # yet been exported, then call {Exporter#force_flush}.
          #
          # This method should only be called in cases where it is absolutely
          # necessary, such as when using some FaaS providers that may suspend
          # the process after an invocation, but before the `Processor` exports
          # the completed log records.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred, TIMEOUT if a timeout occurred.
          # TODO: Should a rescue/handle error be added here for non-specific failures?
          def force_flush(timeout: nil)
            return if @stopped

            @log_record_exporter&.force_flush(timeout: timeout) || SUCCESS
          end

          # Called when {LoggerProvider#shutdown} is called.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred, TIMEOUT if a timeout occurred.
          # TODO: Should a rescue/handle error be added here for non-specific failures?
          def shutdown(timeout: nil)
            return if @stopped

            @log_record_exporter&.shutdown(timeout: timeout) || SUCCESS
          ensure
            @stopped = true
          end
        end
      end
    end
  end
end
