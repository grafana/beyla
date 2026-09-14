# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Logs
      module Export
        # LogRecordExporter describes a duck type. It is not required to
        # subclass this class to provide an implementation of LogRecordExporter,
        # provided the interface is satisfied. LogRecordExporter allows
        # different tracing services to export log record data in their own format.
        #
        # To export data an exporter MUST be registered to the {LoggerProvider}
        # using a {LogRecordProcessor} implementation.
        class LogRecordExporter
          def initialize
            @stopped = false
          end

          # Called to export {LogRecordData}s.
          #
          # @param [Enumerable<LogRecordData>] log_record_data the list of
          # {LogRecordData} to be exported.
          # @param [optional Numeric] timeout An optional timeout in seconds.
          #
          # @return [Integer] the result of the export.
          def export(log_record_data, timeout: nil)
            return SUCCESS unless @stopped

            FAILURE
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
          def shutdown(timeout: nil)
            @stopped = true
            SUCCESS
          end
        end
      end
    end
  end
end
