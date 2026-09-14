# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/sdk/configurator'

module OpenTelemetry
  module SDK
    module Logs
      # The ConfiguratorPatch implements a hook to configure the logs portion
      # of the SDK.
      module ConfiguratorPatch
        def add_log_record_processor(log_record_processor)
          @log_record_processors << log_record_processor
        end

        private

        def initialize
          super
          @log_record_processors = []
        end

        # The logs_configuration_hook method is where we define the setup
        # process for logs SDK.
        def logs_configuration_hook
          OpenTelemetry.logger_provider = Logs::LoggerProvider.new(resource: @resource)
          configure_log_record_processors
        end

        def configure_log_record_processors
          processors = @log_record_processors.empty? ? wrapped_log_exporters_from_env.compact : @log_record_processors
          processors.each { |p| OpenTelemetry.logger_provider.add_log_record_processor(p) }
        end

        def wrapped_log_exporters_from_env
          exporters = ENV.fetch('OTEL_LOGS_EXPORTER', 'otlp')

          exporters.split(',').map do |exporter|
            case exporter.strip
            when 'none' then nil
            when 'console' then Logs::Export::SimpleLogRecordProcessor.new(Logs::Export::ConsoleLogRecordExporter.new)
            when 'otlp'
              otlp_protocol = ENV['OTEL_EXPORTER_OTLP_LOGS_PROTOCOL'] || ENV['OTEL_EXPORTER_OTLP_PROTOCOL'] || 'http/protobuf'

              if otlp_protocol != 'http/protobuf'
                OpenTelemetry.logger.warn "The #{otlp_protocol} transport protocol is not supported by the OTLP exporter, log_records will not be exported."
                nil
              else
                begin
                  Logs::Export::BatchLogRecordProcessor.new(OpenTelemetry::Exporter::OTLP::Logs::LogsExporter.new)
                rescue NameError
                  OpenTelemetry.logger.warn 'The otlp logs exporter cannot be configured - please add opentelemetry-exporter-otlp-logs to your Gemfile. Logs will not be exported'
                  nil
                end
              end
            else
              OpenTelemetry.logger.warn "The #{exporter} exporter is unknown and cannot be configured, log records will not be exported"
              nil
            end
          end
        end
      end
    end
  end
end

OpenTelemetry::SDK::Configurator.prepend(OpenTelemetry::SDK::Logs::ConfiguratorPatch)
