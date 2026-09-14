# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Logs
      module Export
        # A LogRecordExporter implementation that can be used to test OpenTelemetry integration.
        #
        # @example Usage in a test suite:
        #   class MyClassTest
        #     def setup
        #       @logger_provider = LoggerProvider.new
        #       @exporter = InMemoryLogRecordExporter.new
        #       @logger_provider.add_log_record_processor(SimpleLogRecordProcessor.new(@exporter))
        #     end
        #
        #     def test_emitted_log_records
        #       log_record = OpenTelemetry::SDK::Logs::LogRecord.new(body: 'log')
        #       @logger_provider.logger.on_emit(log_record, context)
        #
        #       log_records = @exporter.emitted_log_records

        #       refute_nil(log_records)
        #       assert_equal(1, log_records.size)
        #       assert_equal(log_records[0].body, 'log')
        #     end
        #   end
        class InMemoryLogRecordExporter
          # Returns a new instance of the {InMemoryLogRecordExporter}.
          #
          # @return a new instance of the {InMemoryLogRecordExporter}.
          def initialize
            @emitted_log_records = []
            @stopped = false
            @mutex = Mutex.new
          end

          # Returns a frozen array of the emitted {LogRecordData}s, represented by
          # {io.opentelemetry.proto.trace.v1.LogRecord}.
          #
          # @return [Array<LogRecordData>] a frozen array of the emitted {LogRecordData}s.
          def emitted_log_records
            @mutex.synchronize do
              @emitted_log_records.clone.freeze
            end
          end

          # Clears the internal collection of emitted {LogRecord}s.
          #
          # Does not reset the state of this exporter if already shutdown.
          def reset
            @mutex.synchronize do
              @emitted_log_records.clear
            end
          end

          # Called to export {LogRecordData}s.
          #
          # @param [Enumerable<LogRecordData>] log_record_datas the list of {LogRecordData}s to be
          #   exported.
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] the result of the export, SUCCESS or
          #   FAILURE
          def export(log_record_datas, timeout: nil)
            @mutex.synchronize do
              return FAILURE if @stopped

              @emitted_log_records.concat(log_record_datas.to_a)
            end
            SUCCESS
          end

          # Called when {LoggerProvider#force_flush} is called, if this exporter is
          # registered to a {LoggerProvider} object.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred, TIMEOUT if a timeout occurred.
          def force_flush(timeout: nil)
            SUCCESS
          end

          # Called when {LoggerProvider#shutdown} is called, if this exporter is
          # registered to a {LoggerProvider} object.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred, TIMEOUT if a timeout occurred.
          def shutdown(timeout: nil)
            @mutex.synchronize do
              @emitted_log_records.clear
              @stopped = true
            end
            SUCCESS
          end
        end
      end
    end
  end
end
