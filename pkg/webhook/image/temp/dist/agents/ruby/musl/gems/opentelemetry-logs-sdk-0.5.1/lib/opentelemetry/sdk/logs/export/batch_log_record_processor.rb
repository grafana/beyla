# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Logs
      module Export
        # WARNING - The spec has some differences from the LogRecord version of this processor
        # Implementation of the duck type LogRecordProcessor that batches
        # log records exported by the SDK then pushes them to the exporter
        # pipeline.
        #
        # Typically, the BatchLogRecordProcessor will be more suitable for
        # production environments than the SimpleLogRecordProcessor.
        class BatchLogRecordProcessor < LogRecordProcessor # rubocop:disable Metrics/ClassLength
          # Returns a new instance of the {BatchLogRecordProcessor}.
          #
          # @param [LogRecordExporter] exporter The (duck type) LogRecordExporter to where the
          #   recorded LogRecords are pushed after batching.
          # @param [Numeric] exporter_timeout The maximum allowed time to export data.
          #   Defaults to the value of the OTEL_BLRP_EXPORT_TIMEOUT
          #   environment variable, if set, or 30,000 (30 seconds).
          # @param [Numeric] schedule_delay the delay interval between two consecutive exports.
          #   Defaults to the value of the OTEL_BLRP_SCHEDULE_DELAY environment
          #   variable, if set, or 1,000 (1 second).
          # @param [Integer] max_queue_size the maximum queue size in log records.
          #   Defaults to the value of the OTEL_BLRP_MAX_QUEUE_SIZE environment
          #   variable, if set, or 2048.
          # @param [Integer] max_export_batch_size the maximum batch size in log records.
          #   Defaults to the value of the OTEL_BLRP_MAX_EXPORT_BATCH_SIZE environment
          #   variable, if set, or 512.
          #
          # @return a new instance of the {BatchLogRecordProcessor}.
          def initialize(exporter,
                         exporter_timeout: Float(ENV.fetch('OTEL_BLRP_EXPORT_TIMEOUT', 30_000)),
                         schedule_delay: Float(ENV.fetch('OTEL_BLRP_SCHEDULE_DELAY', 1000)),
                         max_queue_size: Integer(ENV.fetch('OTEL_BLRP_MAX_QUEUE_SIZE', 2048)),
                         max_export_batch_size: Integer(ENV.fetch('OTEL_BLRP_MAX_EXPORT_BATCH_SIZE', 512)),
                         start_thread_on_boot: String(ENV['OTEL_RUBY_BLRP_START_THREAD_ON_BOOT']) !~ /false/i)
            unless max_export_batch_size <= max_queue_size
              raise ArgumentError,
                    'max_export_batch_size much be less than or equal to max_queue_size'
            end

            unless Common::Utilities.valid_exporter?(exporter)
              raise ArgumentError,
                    "exporter #{exporter.inspect} does not appear to be a valid exporter"
            end

            @exporter = exporter
            @exporter_timeout_seconds = exporter_timeout / 1000.0
            @mutex = Mutex.new
            @export_mutex = Mutex.new
            @condition = ConditionVariable.new
            @keep_running = true
            @stopped = false
            @delay_seconds = schedule_delay / 1000.0
            @max_queue_size = max_queue_size
            @batch_size = max_export_batch_size
            @log_records = []
            @pid = nil
            @thread = nil
            reset_on_fork(restart_thread: start_thread_on_boot)
          end

          # Adds a log record to the batch. Thread-safe; may block on lock.
          def on_emit(log_record, _context)
            return if @stopped

            lock do
              reset_on_fork
              n = log_records.size + 1 - max_queue_size
              if n.positive?
                log_records.shift(n)
                report_dropped_log_records(n, reason: 'buffer-full')
              end
              log_records << log_record
              @condition.signal if log_records.size > batch_size
            end
          end

          # Export all emitted log records that have not yet been exported to
          # the configured `Exporter`.
          #
          # This method should only be called in cases where it is absolutely
          # necessary, such as when using some FaaS providers that may suspend
          # the process after an invocation, but before the `Processor` exports
          # the completed log records.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred, TIMEOUT if a timeout occurred.
          def force_flush(timeout: nil)
            start_time = OpenTelemetry::Common::Utilities.timeout_timestamp

            snapshot = lock do
              reset_on_fork if @keep_running
              log_records.shift(log_records.size)
            end

            until snapshot.empty?
              remaining_timeout = OpenTelemetry::Common::Utilities.maybe_timeout(timeout, start_time)
              return TIMEOUT if remaining_timeout&.zero?

              batch = snapshot.shift(batch_size).map!(&:to_log_record_data)
              result_code = export_batch(batch, timeout: remaining_timeout)
              return result_code unless result_code == SUCCESS
            end

            @exporter.force_flush(timeout: OpenTelemetry::Common::Utilities.maybe_timeout(timeout, start_time))
          ensure
            # Unshift the remaining log records if we timed out. We drop excess
            # log records from the snapshot because they're older than any
            # records in the buffer.
            lock do
              n = log_records.size + snapshot.size - max_queue_size

              if n.positive?
                snapshot.shift(n)
                report_dropped_log_records(n, reason: 'buffer-full')
              end

              log_records.unshift(*snapshot) unless snapshot.empty?
              @condition.signal if log_records.size > max_queue_size / 2
            end
          end

          # Shuts the consumer thread down and flushes the current accumulated
          # buffer will block until the thread is finished.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred, TIMEOUT if a timeout occurred.
          def shutdown(timeout: nil)
            return if @stopped

            start_time = OpenTelemetry::Common::Utilities.timeout_timestamp
            thread = lock do
              @keep_running = false
              @stopped = true
              @condition.signal
              @thread
            end

            thread&.join(timeout)
            force_flush(timeout: OpenTelemetry::Common::Utilities.maybe_timeout(timeout, start_time))
            dropped_log_records = lock { log_records.size }
            report_dropped_log_records(dropped_log_records, reason: 'terminating') if dropped_log_records.positive?

            @exporter.shutdown(timeout: OpenTelemetry::Common::Utilities.maybe_timeout(timeout, start_time))
          end

          private

          attr_reader :log_records, :max_queue_size, :batch_size

          def work
            loop do
              batch = lock do
                @condition.wait(@mutex, @delay_seconds) if log_records.size < batch_size && @keep_running
                @condition.wait(@mutex, @delay_seconds) while log_records.empty? && @keep_running
                return unless @keep_running

                fetch_batch
              end

              export_batch(batch)
            end
          end

          def reset_on_fork(restart_thread: true)
            pid = Process.pid
            return if @pid == pid

            @pid = pid
            log_records.clear
            @thread = restart_thread ? Thread.new { work } : nil
          rescue ThreadError => e
            OpenTelemetry.handle_error(exception: e, message: 'unexpected error in BatchLogRecordProcessor#reset_on_fork')
          end

          def export_batch(batch, timeout: @exporter_timeout_seconds)
            result_code = @export_mutex.synchronize { @exporter.export(batch, timeout: timeout) }
            report_result(result_code, batch)
            result_code
          rescue StandardError => e
            report_result(FAILURE, batch)
            OpenTelemetry.handle_error(exception: e, message: 'unexpected error in BatchLogRecordProcessor#export_batch')
          end

          def report_result(result_code, batch)
            if result_code == SUCCESS
              OpenTelemetry.logger.debug("Successfully exported #{batch.size} log records")
            else
              OpenTelemetry.handle_error(exception: ExportError.new("Unable to export #{batch.size} log records"))
              OpenTelemetry.logger.error("Result code: #{result_code}")
            end
          end

          def report_dropped_log_records(count, reason:)
            OpenTelemetry.logger.warn("#{count} log record(s) dropped. Reason: #{reason}")
          end

          def fetch_batch
            log_records.shift(@batch_size).map!(&:to_log_record_data)
          end

          def lock(&block)
            @mutex.synchronize(&block)
          end
        end
      end
    end
  end
end
