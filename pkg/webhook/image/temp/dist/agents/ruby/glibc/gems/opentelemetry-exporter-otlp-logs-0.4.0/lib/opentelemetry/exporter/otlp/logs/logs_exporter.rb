# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/common'
require 'opentelemetry/sdk'
require 'opentelemetry-logs-api' # the sdk isn't loading the api, but not sure why
require 'opentelemetry/sdk/logs'
require 'net/http'
require 'zlib'

require 'google/rpc/status_pb'

require 'opentelemetry/proto/common/v1/common_pb'
require 'opentelemetry/proto/resource/v1/resource_pb'
require 'opentelemetry/proto/logs/v1/logs_pb'
require 'opentelemetry/proto/collector/logs/v1/logs_service_pb'

module OpenTelemetry
  module Exporter
    module OTLP
      module Logs
        # An OpenTelemetry log exporter that sends log records over HTTP as Protobuf encoded OTLP ExportLogsServiceRequests.
        class LogsExporter # rubocop:disable Metrics/ClassLength
          SUCCESS = OpenTelemetry::SDK::Logs::Export::SUCCESS
          FAILURE = OpenTelemetry::SDK::Logs::Export::FAILURE
          private_constant(:SUCCESS, :FAILURE)

          # Default timeouts in seconds.
          KEEP_ALIVE_TIMEOUT = 30
          RETRY_COUNT = 5
          private_constant(:KEEP_ALIVE_TIMEOUT, :RETRY_COUNT)

          ERROR_MESSAGE_INVALID_HEADERS = 'headers must be a String with comma-separated URL Encoded UTF-8 k=v pairs or a Hash'
          private_constant(:ERROR_MESSAGE_INVALID_HEADERS)

          DEFAULT_USER_AGENT = "OTel-OTLP-Exporter-Ruby/#{OpenTelemetry::Exporter::OTLP::Logs::VERSION} Ruby/#{RUBY_VERSION} (#{RUBY_PLATFORM}; #{RUBY_ENGINE}/#{RUBY_ENGINE_VERSION})".freeze

          def self.ssl_verify_mode
            if ENV['OTEL_RUBY_EXPORTER_OTLP_SSL_VERIFY_PEER'] == 'true'
              OpenSSL::SSL::VERIFY_PEER
            elsif ENV['OTEL_RUBY_EXPORTER_OTLP_SSL_VERIFY_NONE'] == 'true'
              OpenSSL::SSL::VERIFY_NONE
            else
              OpenSSL::SSL::VERIFY_PEER
            end
          end

          def initialize(endpoint: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_LOGS_ENDPOINT', 'OTEL_EXPORTER_OTLP_ENDPOINT', default: 'http://localhost:4318/v1/logs'),
                         certificate_file: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE', 'OTEL_EXPORTER_OTLP_CERTIFICATE'),
                         client_certificate_file: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE', 'OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE'),
                         client_key_file: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY', 'OTEL_EXPORTER_OTLP_CLIENT_KEY'),
                         ssl_verify_mode: LogsExporter.ssl_verify_mode,
                         headers: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_LOGS_HEADERS', 'OTEL_EXPORTER_OTLP_HEADERS', default: {}),
                         compression: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_LOGS_COMPRESSION', 'OTEL_EXPORTER_OTLP_COMPRESSION', default: 'gzip'),
                         timeout: OpenTelemetry::Common::Utilities.config_opt('OTEL_EXPORTER_OTLP_LOGS_TIMEOUT', 'OTEL_EXPORTER_OTLP_TIMEOUT', default: 10))
            raise ArgumentError, "invalid url for OTLP::Logs::LogsExporter #{endpoint}" unless OpenTelemetry::Common::Utilities.valid_url?(endpoint)
            raise ArgumentError, "unsupported compression key #{compression}" unless compression.nil? || %w[gzip none].include?(compression)

            @uri = if endpoint == ENV['OTEL_EXPORTER_OTLP_ENDPOINT']
                     URI.join(endpoint, 'v1/logs')
                   else
                     URI(endpoint)
                   end

            @http = http_connection(@uri, ssl_verify_mode, certificate_file, client_certificate_file, client_key_file)

            @path = @uri.path
            @headers = prepare_headers(headers)
            @timeout = timeout.to_f
            @compression = compression
            @shutdown = false
          end

          # Called to export sampled {OpenTelemetry::SDK::Logs::LogRecordData} structs.
          #
          # @param [Enumerable<OpenTelemetry::SDK::Logs::LogRecordData>] log_record_data the
          #   list of recorded {OpenTelemetry::SDK::Logs::LogRecordData} structs to be
          #   exported.
          # @param [optional Numeric] timeout An optional timeout in seconds.
          # @return [Integer] the result of the export.
          def export(log_record_data, timeout: nil)
            OpenTelemetry.logger.error('Logs Exporter tried to export, but it has already shut down') if @shutdown
            return FAILURE if @shutdown

            send_bytes(encode(log_record_data), timeout: timeout)
          end

          # Called when {OpenTelemetry::SDK::Logs::LoggerProvider#force_flush} is called, if
          # this exporter is registered to a {OpenTelemetry::SDK::Logs::LoggerProvider}
          # object.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          def force_flush(timeout: nil)
            SUCCESS
          end

          # Called when {OpenTelemetry::SDK::Logs::LoggerProvider#shutdown} is called, if
          # this exporter is registered to a {OpenTelemetry::SDK::Logs::LoggerProvider}
          # object.
          #
          # @param [optional Numeric] timeout An optional timeout in seconds.
          def shutdown(timeout: nil)
            @shutdown = true
            @http.finish if @http.started?
            SUCCESS
          end

          private

          def handle_http_error(response)
            OpenTelemetry.handle_error(message: "OTLP logs exporter received #{response.class.name}, http.code=#{response.code}, for uri: '#{@path}'")
          end

          def http_connection(uri, ssl_verify_mode, certificate_file, client_certificate_file, client_key_file)
            http = Net::HTTP.new(uri.hostname, uri.port)
            http.use_ssl = uri.scheme == 'https'
            http.verify_mode = ssl_verify_mode
            http.ca_file = certificate_file unless certificate_file.nil?
            http.cert = OpenSSL::X509::Certificate.new(File.read(client_certificate_file)) unless client_certificate_file.nil?
            http.key = OpenSSL::PKey::RSA.new(File.read(client_key_file)) unless client_key_file.nil?
            http.keep_alive_timeout = KEEP_ALIVE_TIMEOUT
            http
          end

          # The around_request is a private method that provides an extension
          # point for the exporters network calls. The default behaviour
          # is to not record these operations.
          #
          # An example use case would be to prepend a patch, or extend this class
          # and override this method's behaviour to explicitly record the HTTP request.
          # This would allow you to create log records for your export pipeline.
          def around_request
            OpenTelemetry::Common::Utilities.untraced { yield } # rubocop:disable Style/ExplicitBlockArgument
          end

          def send_bytes(bytes, timeout:) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
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
                handle_http_error(response)
                redo if backoff?(retry_after: response['Retry-After'], retry_count: retry_count += 1)
                FAILURE
              when Net::HTTPRequestTimeOut, Net::HTTPGatewayTimeOut, Net::HTTPBadGateway
                response.body # Read and discard body
                handle_http_error(response)
                redo if backoff?(retry_count: retry_count += 1)
                FAILURE
              when Net::HTTPNotFound
                handle_http_error(response)
                FAILURE
              when Net::HTTPBadRequest, Net::HTTPClientError, Net::HTTPServerError
                log_status(response.body)
                FAILURE
              when Net::HTTPRedirection
                @http.finish
                handle_redirect(response['location'])
                redo if backoff?(retry_after: 0, retry_count: retry_count += 1)
              else
                @http.finish
                handle_http_error(response)
                FAILURE
              end
            rescue Net::OpenTimeout, Net::ReadTimeout => e
              OpenTelemetry.handle_error(exception: e)
              retry if backoff?(retry_count: retry_count += 1)
              return FAILURE
            rescue OpenSSL::SSL::SSLError => e
              OpenTelemetry.handle_error(exception: e)
              retry if backoff?(retry_count: retry_count += 1)
              return FAILURE
            rescue SocketError => e
              OpenTelemetry.handle_error(exception: e)
              retry if backoff?(retry_count: retry_count += 1)
              return FAILURE
            rescue SystemCallError => e
              retry if backoff?(retry_count: retry_count += 1)
              OpenTelemetry.handle_error(exception: e)
              return FAILURE
            rescue EOFError => e
              OpenTelemetry.handle_error(exception: e)
              retry if backoff?(retry_count: retry_count += 1)
              return FAILURE
            rescue Zlib::DataError => e
              OpenTelemetry.handle_error(exception: e)
              retry if backoff?(retry_count: retry_count += 1)
              return FAILURE
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e, message: 'unexpected error in OTLP::Exporter#send_bytes')
              return FAILURE
            end
          ensure
            # Reset timeouts to defaults for the next call.
            @http.open_timeout = @timeout
            @http.read_timeout = @timeout
            @http.write_timeout = @timeout
          end

          def handle_redirect(location)
            # TODO: figure out destination and reinitialize @http and @path
          end

          def log_status(body)
            status = Google::Rpc::Status.decode(body)
            details = status.details.map do |detail|
              klass_or_nil = ::Google::Protobuf::DescriptorPool.generated_pool.lookup(detail.type_name).msgclass
              detail.unpack(klass_or_nil) if klass_or_nil
            end.compact
            OpenTelemetry.handle_error(message: "OTLP logs exporter received rpc.Status{message=#{status.message}, details=#{details}}")
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e, message: 'unexpected error decoding rpc.Status in OTLP::Exporter#log_status')
          end

          def backoff?(retry_count:, retry_after: nil) # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
            return false if retry_count > RETRY_COUNT

            sleep_interval = nil
            unless retry_after.nil?
              sleep_interval =
                begin
                  Integer(retry_after)
                rescue ArgumentError
                  nil
                end
              sleep_interval ||=
                begin
                  Time.httpdate(retry_after) - Time.now
                rescue # rubocop:disable Style/RescueStandardError
                  nil
                end
              sleep_interval = nil unless sleep_interval&.positive?
            end
            sleep_interval ||= rand(2**retry_count)

            sleep(sleep_interval)
            true
          end

          def encode(log_record_data) # rubocop:disable Metrics/MethodLength, Metrics/CyclomaticComplexity
            Opentelemetry::Proto::Collector::Logs::V1::ExportLogsServiceRequest.encode(
              Opentelemetry::Proto::Collector::Logs::V1::ExportLogsServiceRequest.new(
                resource_logs: log_record_data
                               .group_by(&:resource)
                               .map do |resource, log_record_datas|
                                 Opentelemetry::Proto::Logs::V1::ResourceLogs.new(
                                   resource: Opentelemetry::Proto::Resource::V1::Resource.new(
                                     attributes: resource.attribute_enumerator.map { |key, value| as_otlp_key_value(key, value) }
                                   ),
                                   scope_logs: log_record_datas
                                               .group_by(&:instrumentation_scope)
                                               .map do |il, lrd|
                                                 Opentelemetry::Proto::Logs::V1::ScopeLogs.new(
                                                   scope: Opentelemetry::Proto::Common::V1::InstrumentationScope.new(
                                                     name: il.name,
                                                     version: il.version
                                                   ),
                                                   log_records: lrd.map { |lr| as_otlp_log_record(lr) }
                                                 )
                                               end
                                 )
                               end
              )
            )
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e, message: 'unexpected error in OTLP::Exporter#encode')
            nil
          end

          def as_otlp_log_record(log_record_data)
            Opentelemetry::Proto::Logs::V1::LogRecord.new(
              time_unix_nano: log_record_data.timestamp,
              observed_time_unix_nano: log_record_data.observed_timestamp,
              severity_number: log_record_data.severity_number,
              severity_text: log_record_data.severity_text,
              body: as_otlp_any_value(log_record_data.body),
              attributes: log_record_data.attributes&.map { |k, v| as_otlp_key_value(k, v) },
              dropped_attributes_count: log_record_data.total_recorded_attributes - log_record_data.attributes&.size.to_i,
              flags: log_record_data.trace_flags.instance_variable_get(:@flags),
              trace_id: log_record_data.trace_id,
              span_id: log_record_data.span_id
            )
          end

          def as_otlp_key_value(key, value)
            Opentelemetry::Proto::Common::V1::KeyValue.new(key: key, value: as_otlp_any_value(value))
          rescue Encoding::UndefinedConversionError => e
            encoded_value = value.encode('UTF-8', invalid: :replace, undef: :replace, replace: '�')
            OpenTelemetry.handle_error(exception: e, message: "encoding error for key #{key} and value #{encoded_value}")
            Opentelemetry::Proto::Common::V1::KeyValue.new(key: key, value: as_otlp_any_value('Encoding Error'))
          end

          def as_otlp_any_value(value) # rubocop:disable Metrics/CyclomaticComplexity
            result = Opentelemetry::Proto::Common::V1::AnyValue.new
            case value
            when String
              result.string_value = value
            when Integer
              result.int_value = value
            when Float
              result.double_value = value
            when true, false
              result.bool_value = value
            when Array
              values = value.map { |element| as_otlp_any_value(element) }
              result.array_value = Opentelemetry::Proto::Common::V1::ArrayValue.new(values: values)
            when Hash
              values = value.map { |k, v| as_otlp_key_value(k, v) }
              result.kvlist_value = Opentelemetry::Proto::Common::V1::KeyValueList.new(values: values)
            end
            result
          end

          def prepare_headers(config_headers)
            headers = case config_headers
                      when String then parse_headers(config_headers)
                      when Hash then config_headers.dup
                      else
                        raise ArgumentError, ERROR_MESSAGE_INVALID_HEADERS
                      end

            headers['User-Agent'] = "#{headers.fetch('User-Agent', '')} #{DEFAULT_USER_AGENT}".strip

            headers
          end

          def parse_headers(raw)
            entries = raw.split(',')
            raise ArgumentError, ERROR_MESSAGE_INVALID_HEADERS if entries.empty?

            entries.each_with_object({}) do |entry, headers|
              k, v = entry.split('=', 2).map(&URI.method(:decode_uri_component))
              begin
                k = k.to_s.strip
                v = v.to_s.strip
              rescue Encoding::CompatibilityError
                raise ArgumentError, ERROR_MESSAGE_INVALID_HEADERS
              rescue ArgumentError => e
                raise e, ERROR_MESSAGE_INVALID_HEADERS
              end
              raise ArgumentError, ERROR_MESSAGE_INVALID_HEADERS if k.empty? || v.empty?

              headers[k] = v
            end
          end
        end
      end
    end
  end
end
