# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Exporter
    module OTLP
      module Metrics
        # Util module provide essential functionality for exporter
        module Util # rubocop:disable Metrics/ModuleLength
          KEEP_ALIVE_TIMEOUT = 30
          RETRY_COUNT = 5
          ERROR_MESSAGE_INVALID_HEADERS = 'headers must be a String with comma-separated URL Encoded UTF-8 k=v pairs or a Hash'
          DEFAULT_USER_AGENT = "OTel-OTLP-MetricsExporter-Ruby/#{OpenTelemetry::Exporter::OTLP::Metrics::VERSION} Ruby/#{RUBY_VERSION} (#{RUBY_PLATFORM}; #{RUBY_ENGINE}/#{RUBY_ENGINE_VERSION})".freeze

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

          def around_request
            OpenTelemetry::Common::Utilities.untraced { yield } # rubocop:disable Style/ExplicitBlockArgument
          end

          def as_otlp_key_value(key, value)
            Opentelemetry::Proto::Common::V1::KeyValue.new(key: key, value: as_otlp_any_value(value))
          rescue Encoding::UndefinedConversionError => e
            encoded_value = value.encode('UTF-8', invalid: :replace, undef: :replace, replace: '�')
            OpenTelemetry.handle_error(exception: e, message: "encoding error for key #{key} and value #{encoded_value}")
            Opentelemetry::Proto::Common::V1::KeyValue.new(key: key, value: as_otlp_any_value('Encoding Error'))
          end

          def as_otlp_any_value(value)
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

          def backoff?(retry_count:, reason:, retry_after: nil)
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

          def log_status(body)
            status = Google::Rpc::Status.decode(body)
            details = status.details.map do |detail|
              type_name = detail.type_url.to_s.split('/').last.to_s
              klass_or_nil = ::Google::Protobuf::DescriptorPool.generated_pool.lookup(type_name)&.msgclass
              detail.unpack(klass_or_nil) if klass_or_nil
            end.compact
            OpenTelemetry.handle_error(message: "OTLP metrics_exporter received rpc.Status{message=#{status.message}, details=#{details}}")
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e, message: 'unexpected error decoding rpc.Status in OTLP::MetricsExporter#log_status')
          end

          def handle_redirect(location); end
        end
      end
    end
  end
end
