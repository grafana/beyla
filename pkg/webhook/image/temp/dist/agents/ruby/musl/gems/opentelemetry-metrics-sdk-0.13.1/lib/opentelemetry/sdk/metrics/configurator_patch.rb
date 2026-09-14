# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      # The ConfiguratorPatch implements a hook to configure the metrics
      # portion of the SDK.
      module ConfiguratorPatch
        def add_metric_reader(metric_reader)
          @metric_readers << metric_reader
        end

        private

        def initialize
          super
          @metric_readers = []
        end

        # The metrics_configuration_hook method is where we define the setup process for the metrics SDK.
        def metrics_configuration_hook
          OpenTelemetry.meter_provider = Metrics::MeterProvider.new(resource: @resource)
          configure_metric_readers
          attach_fork_hooks!
        end

        def configure_metric_readers
          readers = @metric_readers.empty? ? wrapped_metric_exporters_from_env.compact : @metric_readers
          readers.each { |r| OpenTelemetry.meter_provider.add_metric_reader(r) }
        end

        def wrapped_metric_exporters_from_env
          exporters = ENV.fetch('OTEL_METRICS_EXPORTER', 'otlp')
          exporters.split(',').map do |exporter|
            case exporter.strip
            when 'none' then nil
            when 'console' then OpenTelemetry.meter_provider.add_metric_reader(Metrics::Export::PeriodicMetricReader.new(exporter: Metrics::Export::ConsoleMetricPullExporter.new))
            when 'in-memory' then OpenTelemetry.meter_provider.add_metric_reader(Metrics::Export::InMemoryMetricPullExporter.new)
            when 'otlp'
              begin
                OpenTelemetry.meter_provider.add_metric_reader(Metrics::Export::PeriodicMetricReader.new(exporter: OpenTelemetry::Exporter::OTLP::Metrics::MetricsExporter.new))
              rescue NameError
                OpenTelemetry.logger.warn 'The otlp metrics exporter cannot be configured - please add opentelemetry-exporter-otlp-metrics to your Gemfile, metrics will not be exported'
                nil
              end
            else
              OpenTelemetry.logger.warn "The #{exporter} exporter is unknown and cannot be configured, metrics will not be exported"
              nil
            end
          end
        end

        def attach_fork_hooks!
          ForkHooks.attach!
        end
      end
    end
  end
end

OpenTelemetry::SDK::Configurator.prepend(OpenTelemetry::SDK::Metrics::ConfiguratorPatch)
