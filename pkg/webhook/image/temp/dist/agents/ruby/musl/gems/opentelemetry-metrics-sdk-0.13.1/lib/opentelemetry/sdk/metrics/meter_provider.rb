# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    # The Metrics module contains the OpenTelemetry metrics reference
    # implementation.
    module Metrics
      # {MeterProvider} is the SDK implementation of {OpenTelemetry::Metrics::MeterProvider}.
      # rubocop:disable Metrics/ClassLength
      class MeterProvider < OpenTelemetry::Metrics::MeterProvider
        Key = Struct.new(:name, :version)
        private_constant(:Key)

        attr_reader :resource, :metric_readers, :registered_views, :exemplar_filter

        def initialize(resource: OpenTelemetry::SDK::Resources::Resource.create)
          @mutex = Mutex.new
          @meter_registry = {}
          @stopped = false
          @metric_readers = []
          @resource = resource
          @registered_views = []
          exemplar_filter_setup
        end

        # Returns a {Meter} instance.
        #
        # @param [String] name Instrumentation package name
        # @param [optional String] version Instrumentation package version
        #
        # @return [Meter]
        def meter(name, version: nil)
          version ||= ''
          if @stopped
            OpenTelemetry.logger.warn 'calling MeterProvider#meter after shutdown, a noop meter will be returned.'
            OpenTelemetry::Metrics::Meter.new
          else
            OpenTelemetry.logger.warn "Invalid meter name provided: #{name.nil? ? 'nil' : 'empty'} value" if name.to_s.empty?
            @mutex.synchronize { @meter_registry[Key.new(name, version)] ||= Meter.new(name, version, self) }
          end
        end

        # Attempts to stop all the activity for this {MeterProvider}.
        #
        # Calls MetricReader#shutdown for all registered MetricReaders.
        #
        # After this is called all the newly created {Meter}s will be no-op.
        #
        # @param [optional Numeric] timeout An optional timeout in seconds.
        # @return [Integer] Export::SUCCESS if no error occurred, Export::FAILURE if
        #   a non-specific failure occurred, Export::TIMEOUT if a timeout occurred.
        def shutdown(timeout: nil)
          @mutex.synchronize do
            if @stopped
              OpenTelemetry.logger.warn('calling MetricProvider#shutdown multiple times.')
              Export::FAILURE
            else
              start_time = OpenTelemetry::Common::Utilities.timeout_timestamp
              results = @metric_readers.map do |metric_reader|
                remaining_timeout = OpenTelemetry::Common::Utilities.maybe_timeout(timeout, start_time)
                if remaining_timeout&.zero?
                  Export::TIMEOUT
                else
                  metric_reader.shutdown(timeout: remaining_timeout)
                end
              end

              @stopped = true
              results.max || Export::SUCCESS
            end
          end
        end

        # This method provides a way for provider to notify the registered
        # {MetricReader} instances, so they can do as much as they could to consume
        # or send the metrics. Note: unlike Push Metric Exporter which can send data on
        # its own schedule, Pull Metric Exporter can only send the data when it is
        # being asked by the scraper, so ForceFlush would not make much sense.
        #
        # @param [optional Numeric] timeout An optional timeout in seconds.
        # @return [Integer] Export::SUCCESS if no error occurred, Export::FAILURE if
        #   a non-specific failure occurred, Export::TIMEOUT if a timeout occurred.
        def force_flush(timeout: nil)
          @mutex.synchronize do
            if @stopped
              Export::SUCCESS
            else
              start_time = OpenTelemetry::Common::Utilities.timeout_timestamp
              results = @metric_readers.map do |metric_reader|
                remaining_timeout = OpenTelemetry::Common::Utilities.maybe_timeout(timeout, start_time)
                if remaining_timeout&.zero?
                  Export::TIMEOUT
                else
                  metric_reader.force_flush(timeout: remaining_timeout)
                end
              end

              results.max || Export::SUCCESS
            end
          end
        end

        # Adds a new MetricReader to this {MeterProvider}.
        #
        # @param metric_reader the new MetricReader to be added.
        def add_metric_reader(metric_reader)
          @mutex.synchronize do
            if @stopped
              OpenTelemetry.logger.warn('calling MetricProvider#add_metric_reader after shutdown.')
            else
              @metric_readers.push(metric_reader)
              @meter_registry.each_value { |meter| meter.add_metric_reader(metric_reader) }
            end

            nil
          end
        end

        # @api private
        def register_synchronous_instrument(instrument)
          @mutex.synchronize do
            @metric_readers.each do |mr|
              instrument.register_with_new_metric_store(mr.metric_store)
            end
          end
        end
        alias register_asynchronous_instrument register_synchronous_instrument

        # spec: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/configuration/sdk-environment-variables.md#exemplar
        # this is one way to turn on the exemplar (exemplar should be turned off by default)
        def exemplar_filter_setup
          case ENV['OTEL_METRICS_EXEMPLAR_FILTER']
          when 'always_on'
            @exemplar_filter = Exemplar::AlwaysOnExemplarFilter
          when 'trace_based'
            @exemplar_filter = Exemplar::TraceBasedExemplarFilter
          when 'always_off'
            @exemplar_filter = Exemplar::AlwaysOffExemplarFilter
          else
            OpenTelemetry.logger.warn("OTEL_METRICS_EXEMPLAR_FILTER #{ENV['OTEL_METRICS_EXEMPLAR_FILTER']} is not part of the provided exemplar filters. Exemplar is off.")
            @exemplar_filter = Exemplar::AlwaysOffExemplarFilter
          end
        end

        # Adds a new exemplar_filter to replace exist exemplar_filter
        # Default to TraceBasedExemplarFilter
        #
        # @param exemplar_filter the new ExemplarFilter to be added.
        def enable_exemplar_filter(exemplar_filter: Exemplar::TraceBasedExemplarFilter)
          @exemplar_filter = exemplar_filter
        end

        # turn off exemplar_filter by setting the exemplar_fitler to AlwaysOffExemplarFilter
        def disable_exemplar_filter
          @exemplar_filter = Exemplar::AlwaysOffExemplarFilter
        end

        # A View provides SDK users with the flexibility to customize the metrics that are output by the SDK.
        #
        # Example:
        #
        #   OpenTelemetry.meter_provider.add_view('test', :aggregation => Aggregation::Drop.new,
        #                                         :type => :counter, :unit => 'smidgen',
        #                                         :meter_name => 'test', :meter_version => '1.0')
        #
        #
        # @param [String] name Name of the view.
        # @param [optional Hash] options For more precise matching, {View} and {MetricsStream}
        #   options may include:
        #     aggregation: An instance of an aggregation class, e.g. {ExplicitBucketHistogram}, {Sum}, {LastValue}
        #     type: A Symbol representing the instrument kind, e.g. :observable_gauge, :counter
        #     unit: A String matching an instrumentation unit, e.g. 'smidgen'
        #     meter_name: A String matching a meter name, e.g. meter_provider.meter('sample_meter_name', version: '1.2.0'), would be 'sample_meter_name'
        #     meter_version: A String matching a meter version, e.g. meter_provider.meter('sample_meter_name', version: '1.2.0'), would be '1.2.0'
        #
        # @return [nil] returns nil
        #
        def add_view(name, **options)
          # TODO: add schema_url as part of options
          @registered_views << View::RegisteredView.new(name, **options)
          nil
        end
      end
      # rubocop:enable Metrics/ClassLength
    end
  end
end
