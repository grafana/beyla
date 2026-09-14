# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/common'
require 'opentelemetry/sdk'
require 'net/http'
require 'zlib'

require 'google/rpc/status_pb'

require 'opentelemetry/proto/common/v1/common_pb'
require 'opentelemetry/proto/resource/v1/resource_pb'
require 'opentelemetry/proto/metrics/v1/metrics_pb'
require 'opentelemetry/proto/collector/metrics/v1/metrics_service_pb'

require 'opentelemetry/metrics'
require 'opentelemetry/sdk/metrics'

require_relative './util'

module OpenTelemetry
  module Exporter
    module OTLP
      module Metrics
        # An OpenTelemetry metrics exporter that sends metrics over HTTP as Protobuf encoded OTLP ExportMetricsServiceRequest.
        class MetricsExporter < ::OpenTelemetry::SDK::Metrics::Export::MetricReader
          include Util

          attr_reader :metric_snapshots

          SUCCESS = OpenTelemetry::SDK::Metrics::Export::SUCCESS
          FAILURE = OpenTelemetry::SDK::Metrics::Export::FAILURE
          private_constant(:SUCCESS, :FAILURE)

          def self.ssl_verify_mode
            if ENV.key?('OTEL_RUBY_EXPORTER_OTLP_SSL_VERIFY_PEER')
              OpenSSL::SSL::VERIFY_PEER
            elsif ENV.key?('OTEL_RUBY_EXPORTER_OTLP_SSL_VERIFY_NONE')
              OpenSSL::SSL::VERIFY_NONE
            else
              OpenSSL::SSL::VERIFY_PEER
            end
          end

          def initialize(endpoint: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_METRICS_ENDPOINT', 'OTEL_EXPORTER_OTLP_ENDPOINT', default: 'http://localhost:4318/v1/metrics'),
                         certificate_file: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE', 'OTEL_EXPORTER_OTLP_CERTIFICATE'),
                         client_certificate_file: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_METRICS_CLIENT_CERTIFICATE', 'OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE'),
                         client_key_file: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_METRICS_CLIENT_KEY', 'OTEL_EXPORTER_OTLP_CLIENT_KEY'),
                         ssl_verify_mode: MetricsExporter.ssl_verify_mode,
                         headers: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_METRICS_HEADERS', 'OTEL_EXPORTER_OTLP_HEADERS', default: {}),
                         compression: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_METRICS_COMPRESSION', 'OTEL_EXPORTER_OTLP_COMPRESSION', default: 'gzip'),
                         timeout: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_METRICS_TIMEOUT', 'OTEL_EXPORTER_OTLP_TIMEOUT', default: 10))
            raise ArgumentError, "invalid url for OTLP::MetricsExporter #{endpoint}" unless OpenTelemetry::Common::Utilities.valid_url?(endpoint)
            raise ArgumentError, "unsupported compression key #{compression}" unless compression.nil? || %w[gzip none].include?(compression)

            # create the MetricStore object
            super()

            @uri = if endpoint == ENV['OTEL_EXPORTER_OTLP_ENDPOINT']
                     URI.join(endpoint, 'v1/metrics')
                   else
                     URI(endpoint)
                   end

            @http = http_connection(@uri, ssl_verify_mode, certificate_file, client_certificate_file, client_key_file)

            @path = @uri.path
            @headers = prepare_headers(headers)
            @timeout = timeout.to_f
            @compression = compression
            @mutex = Mutex.new
            @shutdown = false
          end

          # consolidate the metrics data into the form of MetricData
          #
          # return MetricData
          def pull
            export(collect)
          end

          # metrics Array[MetricData]
          def export(metrics, timeout: nil)
            @mutex.synchronize do
              send_bytes(encode(metrics), timeout: timeout)
            end
          end

          def send_bytes(bytes, timeout:)
            return FAILURE if bytes.nil?

            request = Net::HTTP::Post.new(@path)

            if @compression == 'gzip'
              request.add_field('Content-Encoding', 'gzip')
              body = Zlib.gzip(bytes)
            else
              body = bytes
            end

            request.body = body
            request.add_field('Content-Type', 'application/x-protobuf')
            @headers.each { |key, value| request.add_field(key, value) }

            retry_count = 0
            timeout ||= @timeout
            start_time = OpenTelemetry::Common::Utilities.timeout_timestamp

            around_request do
              remaining_timeout = OpenTelemetry::Common::Utilities.maybe_timeout(timeout, start_time)
              return FAILURE if remaining_timeout.zero?

              @http.open_timeout = remaining_timeout
              @http.read_timeout = remaining_timeout
              @http.write_timeout = remaining_timeout
              @http.start unless @http.started?
              response = @http.request(request)
              case response
              when Net::HTTPSuccess
                response.body # Read and discard body
                SUCCESS
              when Net::HTTPServiceUnavailable, Net::HTTPTooManyRequests
                response.body # Read and discard body
                redo if backoff?(retry_after: response['Retry-After'], retry_count: retry_count += 1, reason: response.code)
                OpenTelemetry.logger.warn('Net::HTTPServiceUnavailable/Net::HTTPTooManyRequests in MetricsExporter#send_bytes')
                FAILURE
              when Net::HTTPRequestTimeOut, Net::HTTPGatewayTimeOut, Net::HTTPBadGateway
                response.body # Read and discard body
                redo if backoff?(retry_count: retry_count += 1, reason: response.code)
                OpenTelemetry.logger.warn('Net::HTTPRequestTimeOut/Net::HTTPGatewayTimeOut/Net::HTTPBadGateway in MetricsExporter#send_bytes')
                FAILURE
              when Net::HTTPNotFound
                OpenTelemetry.handle_error(message: "OTLP metrics_exporter received http.code=404 for uri: '#{@path}'")
                FAILURE
              when Net::HTTPBadRequest, Net::HTTPClientError, Net::HTTPServerError
                log_status(response.body)
                OpenTelemetry.logger.warn('Net::HTTPBadRequest/Net::HTTPClientError/Net::HTTPServerError in MetricsExporter#send_bytes')
                FAILURE
              when Net::HTTPRedirection
                @http.finish
                handle_redirect(response['location'])
                redo if backoff?(retry_after: 0, retry_count: retry_count += 1, reason: response.code)
              else
                @http.finish
                OpenTelemetry.logger.warn("Unexpected error in OTLP::MetricsExporter#send_bytes - #{response.message}")
                FAILURE
              end
            rescue Net::OpenTimeout, Net::ReadTimeout
              retry if backoff?(retry_count: retry_count += 1, reason: 'timeout')
              OpenTelemetry.logger.warn('Net::OpenTimeout/Net::ReadTimeout in MetricsExporter#send_bytes')
              return FAILURE
            rescue OpenSSL::SSL::SSLError
              retry if backoff?(retry_count: retry_count += 1, reason: 'openssl_error')
              OpenTelemetry.logger.warn('OpenSSL::SSL::SSLError in MetricsExporter#send_bytes')
              return FAILURE
            rescue SocketError
              retry if backoff?(retry_count: retry_count += 1, reason: 'socket_error')
              OpenTelemetry.logger.warn('SocketError in MetricsExporter#send_bytes')
              return FAILURE
            rescue SystemCallError => e
              retry if backoff?(retry_count: retry_count += 1, reason: e.class.name)
              OpenTelemetry.logger.warn('SystemCallError in MetricsExporter#send_bytes')
              return FAILURE
            rescue EOFError
              retry if backoff?(retry_count: retry_count += 1, reason: 'eof_error')
              OpenTelemetry.logger.warn('EOFError in MetricsExporter#send_bytes')
              return FAILURE
            rescue Zlib::DataError
              retry if backoff?(retry_count: retry_count += 1, reason: 'zlib_error')
              OpenTelemetry.logger.warn('Zlib::DataError in MetricsExporter#send_bytes')
              return FAILURE
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e, message: 'unexpected error in OTLP::MetricsExporter#send_bytes')
              return FAILURE
            end
          ensure
            # Reset timeouts to defaults for the next call.
            @http.open_timeout = @timeout
            @http.read_timeout = @timeout
            @http.write_timeout = @timeout
          end

          def encode(metrics_data)
            Opentelemetry::Proto::Collector::Metrics::V1::ExportMetricsServiceRequest.encode(
              Opentelemetry::Proto::Collector::Metrics::V1::ExportMetricsServiceRequest.new(
                resource_metrics: metrics_data
                                  .group_by(&:resource)
                                  .map do |resource, scope_metrics|
                                    Opentelemetry::Proto::Metrics::V1::ResourceMetrics.new(
                                      resource: Opentelemetry::Proto::Resource::V1::Resource.new(
                                        attributes: resource.attribute_enumerator.map { |key, value| as_otlp_key_value(key, value) }
                                      ),
                                      scope_metrics: scope_metrics
                                                     .group_by(&:instrumentation_scope)
                                                     .map do |instrumentation_scope, metrics|
                                                       Opentelemetry::Proto::Metrics::V1::ScopeMetrics.new(
                                                         scope: Opentelemetry::Proto::Common::V1::InstrumentationScope.new(
                                                           name: instrumentation_scope.name,
                                                           version: instrumentation_scope.version
                                                         ),
                                                         metrics: metrics.map { |sd| as_otlp_metrics(sd) }
                                                       )
                                                     end
                                    )
                                  end
              )
            )
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e, message: 'unexpected error in OTLP::MetricsExporter#encode')
            nil
          end

          # metrics_pb has following type of data: :gauge, :sum, :histogram, :exponential_histogram, :summary
          # current metric sdk only implements instrument: :counter -> :sum, :histogram -> :histogram, :gauge -> :gauge
          #
          # metrics [MetricData]
          def as_otlp_metrics(metrics)
            case metrics.instrument_kind
            when :observable_gauge, :gauge
              Opentelemetry::Proto::Metrics::V1::Metric.new(
                name: metrics.name,
                description: metrics.description,
                unit: metrics.unit,
                gauge: Opentelemetry::Proto::Metrics::V1::Gauge.new(
                  data_points: metrics.data_points.map do |ndp|
                    number_data_point(ndp)
                  end
                )
              )

            when :counter, :up_down_counter, :observable_counter, :observable_up_down_counter
              Opentelemetry::Proto::Metrics::V1::Metric.new(
                name: metrics.name,
                description: metrics.description,
                unit: metrics.unit,
                sum: Opentelemetry::Proto::Metrics::V1::Sum.new(
                  aggregation_temporality: as_otlp_aggregation_temporality(metrics.aggregation_temporality),
                  data_points: metrics.data_points.map do |ndp|
                    number_data_point(ndp)
                  end,
                  is_monotonic: metrics.is_monotonic
                )
              )

            when :histogram
              histogram_data_point(metrics)

            end
          end

          def as_otlp_aggregation_temporality(type)
            case type
            when :delta then Opentelemetry::Proto::Metrics::V1::AggregationTemporality::AGGREGATION_TEMPORALITY_DELTA
            when :cumulative then Opentelemetry::Proto::Metrics::V1::AggregationTemporality::AGGREGATION_TEMPORALITY_CUMULATIVE
            else Opentelemetry::Proto::Metrics::V1::AggregationTemporality::AGGREGATION_TEMPORALITY_UNSPECIFIED
            end
          end

          def histogram_data_point(metrics)
            return if metrics.data_points.empty?

            if metrics.data_points.first.instance_of?(OpenTelemetry::SDK::Metrics::Aggregation::ExponentialHistogramDataPoint)
              Opentelemetry::Proto::Metrics::V1::Metric.new(
                name: metrics.name,
                description: metrics.description,
                unit: metrics.unit,
                exponential_histogram: Opentelemetry::Proto::Metrics::V1::ExponentialHistogram.new(
                  aggregation_temporality: as_otlp_aggregation_temporality(metrics.aggregation_temporality),
                  data_points: metrics.data_points.map do |ehdp|
                    exponential_histogram_data_point(ehdp)
                  end
                )
              )
            elsif metrics.data_points.first.instance_of?(OpenTelemetry::SDK::Metrics::Aggregation::HistogramDataPoint)
              Opentelemetry::Proto::Metrics::V1::Metric.new(
                name: metrics.name,
                description: metrics.description,
                unit: metrics.unit,
                histogram: Opentelemetry::Proto::Metrics::V1::Histogram.new(
                  aggregation_temporality: as_otlp_aggregation_temporality(metrics.aggregation_temporality),
                  data_points: metrics.data_points.map do |hdp|
                    explicit_histogram_data_point(hdp)
                  end
                )
              )
            end
          end

          def explicit_histogram_data_point(hdp)
            Opentelemetry::Proto::Metrics::V1::HistogramDataPoint.new(
              attributes: hdp.attributes.map { |k, v| as_otlp_key_value(k, v) },
              start_time_unix_nano: hdp.start_time_unix_nano,
              time_unix_nano: hdp.time_unix_nano,
              count: hdp.count,
              sum: hdp.sum,
              bucket_counts: hdp.bucket_counts,
              explicit_bounds: hdp.explicit_bounds,
              exemplars: as_otlp_exemplars(hdp.exemplars),
              min: hdp.min,
              max: hdp.max
            )
          end

          def exponential_histogram_data_point(ehdp)
            Opentelemetry::Proto::Metrics::V1::ExponentialHistogramDataPoint.new(
              attributes: ehdp.attributes.map { |k, v| as_otlp_key_value(k, v) },
              start_time_unix_nano: ehdp.start_time_unix_nano,
              time_unix_nano: ehdp.time_unix_nano,
              count: ehdp.count,
              sum: ehdp.sum,
              scale: ehdp.scale,
              zero_count: ehdp.zero_count,
              positive: Opentelemetry::Proto::Metrics::V1::ExponentialHistogramDataPoint::Buckets.new(
                offset: ehdp.positive.offset,
                bucket_counts: ehdp.positive.counts
              ),
              negative: Opentelemetry::Proto::Metrics::V1::ExponentialHistogramDataPoint::Buckets.new(
                offset: ehdp.negative.offset,
                bucket_counts: ehdp.negative.counts
              ),
              flags: ehdp.flags,
              exemplars: as_otlp_exemplars(ehdp.exemplars),
              min: ehdp.min,
              max: ehdp.max,
              zero_threshold: ehdp.zero_threshold
            )
          end

          def number_data_point(ndp)
            args = {
              attributes: ndp.attributes.map { |k, v| as_otlp_key_value(k, v) },
              start_time_unix_nano: ndp.start_time_unix_nano,
              time_unix_nano: ndp.time_unix_nano,
              exemplars: as_otlp_exemplars(ndp.exemplars)
            }

            if ndp.value.is_a?(Float)
              args[:as_double] = ndp.value
            else
              args[:as_int] = ndp.value
            end

            Opentelemetry::Proto::Metrics::V1::NumberDataPoint.new(**args)
          end

          def as_otlp_exemplars(exemplars)
            exemplars&.map { |ex| as_otlp_exemplar(ex) } || []
          end

          def as_otlp_exemplar(exemplar)
            args = {
              time_unix_nano: exemplar.time_unix_nano,
              span_id: exemplar.span_id,
              trace_id: exemplar.trace_id
            }

            # Add filtered_attributes if present
            args[:filtered_attributes] = exemplar.filtered_attributes.map { |k, v| as_otlp_key_value(k, v) } if exemplar.filtered_attributes

            # Set value based on type
            if exemplar.value.is_a?(Float)
              args[:as_double] = exemplar.value
            else
              args[:as_int] = exemplar.value
            end

            Opentelemetry::Proto::Metrics::V1::Exemplar.new(**args)
          end

          # may not need this
          def reset
            SUCCESS
          end

          def force_flush(timeout: nil)
            SUCCESS
          end

          def shutdown(timeout: nil)
            @shutdown = true
            SUCCESS
          end
        end
      end
    end
  end
end
