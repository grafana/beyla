# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Export
        # PeriodicMetricReader provides a minimal example implementation.
        class PeriodicMetricReader < MetricReader
          # Returns a new instance of the {PeriodicMetricReader}.
          #
          # @param [Integer] export_interval_millis the maximum interval time.
          #   Defaults to the value of the OTEL_METRIC_EXPORT_INTERVAL environment
          #   variable, if set, or 60_000.
          # @param [Integer] export_timeout_millis the maximum export timeout.
          #   Defaults to the value of the OTEL_METRIC_EXPORT_TIMEOUT environment
          #   variable, if set, or 30_000.
          # @param [MetricReader] exporter the (duck type) MetricReader to where the
          #   recorded metrics are pushed after certain interval.
          #
          # @return a new instance of the {PeriodicMetricReader}.
          def initialize(export_interval_millis: Float(ENV.fetch('OTEL_METRIC_EXPORT_INTERVAL', 60_000)),
                         export_timeout_millis: Float(ENV.fetch('OTEL_METRIC_EXPORT_TIMEOUT', 30_000)),
                         exporter: nil)
            super()

            @export_interval = export_interval_millis / 1000.0
            @export_timeout = export_timeout_millis / 1000.0
            @exporter = exporter
            @thread   = nil
            @continue = false
            @mutex = Mutex.new
            @condition = ConditionVariable.new
            @export_mutex = Mutex.new

            start
          end

          # Shuts the @thread down and set @continue to false; it will block
          # until the shutdown thread is finished.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred.
          def shutdown(timeout: nil)
            thread = lock do
              @continue = false # force termination in next iteration
              @condition.signal
              @thread
            end
            thread&.join(@export_interval)
            @exporter.force_flush if @exporter.respond_to?(:force_flush)
            @exporter.shutdown
            Export::SUCCESS
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e, message: 'Fail to shutdown PeriodicMetricReader.')
            Export::FAILURE
          end

          # Export all metrics to the configured `Exporter` that have not yet
          # been exported.
          #
          # This method should only be called in cases where it is absolutely
          # necessary, such as when using some FaaS providers that may suspend
          # the process after an invocation, but before the `PeriodicMetricReader` exports
          # the completed metrics.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred.
          def force_flush(timeout: nil)
            export(timeout:)
            Export::SUCCESS
          rescue StandardError
            Export::FAILURE
          end

          def after_fork
            @exporter.reset if @exporter.respond_to?(:reset)
            collect # move past previously reported metrics from parent process
            @thread = nil
            start
          end

          # Check both @thread and @continue object to determine if current
          # PeriodicMetricReader is still alive. If one of them is true/alive,
          # then PeriodicMetricReader is determined as alive
          def alive?
            @continue || @thread.alive?
          end

          private

          # Start a thread that continously export metrics within fixed duration.
          # The wait mechanism is using to check @mutex lock with conditional variable
          def start
            @continue = true
            if @exporter.nil?
              OpenTelemetry.logger.warn 'Missing exporter in PeriodicMetricReader.'
            elsif @thread&.alive?
              OpenTelemetry.logger.warn 'PeriodicMetricReader is still running. Please shutdown it if it needs to restart.'
            else
              @thread = Thread.new do
                while @continue
                  lock do
                    @condition.wait(@mutex, @export_interval)
                    export(timeout: @export_timeout)
                  end
                end
              end
            end
          end

          # Helper function for the defined exporter to export metrics.
          # It only exports if the collected metrics are not an empty array (collect returns an Array).
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] SUCCESS if no error occurred, FAILURE if a
          #   non-specific failure occurred
          def export(timeout: nil)
            @export_mutex.synchronize do
              collected_metrics = collect
              result_code = @exporter.export(collected_metrics, timeout: timeout || @export_timeout) unless collected_metrics.empty?
              report_result(result_code)
              result_code
            end
          end

          def report_result(result_code)
            OpenTelemetry.logger.debug 'Successfully exported metrics' if result_code == Export::SUCCESS
          end

          def lock(&block)
            @mutex.synchronize(&block)
          end
        end
      end
    end
  end
end
