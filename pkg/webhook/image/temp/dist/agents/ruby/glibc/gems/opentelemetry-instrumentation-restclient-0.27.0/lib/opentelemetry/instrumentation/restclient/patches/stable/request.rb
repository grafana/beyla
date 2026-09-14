# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module RestClient
      module Patches
        module Stable
          # Module to prepend to RestClient::Request for instrumentation
          module Request
            # Constant for the HTTP status range
            HTTP_STATUS_SUCCESS_RANGE = (100..399)

            def execute(&)
              trace_request do |_span|
                super
              end
            end

            private

            def create_request_span
              http_method = method.upcase
              instrumentation_attrs = {
                'http.request.method' => http_method.to_s,
                'url.full' => OpenTelemetry::Common::Utilities.cleanse_url(url)
              }
              instrumentation_config = RestClient::Instrumentation.instance.config
              instrumentation_attrs['peer.service'] = instrumentation_config[:peer_service] if instrumentation_config[:peer_service]
              span = tracer.start_span(
                http_method.to_s,
                attributes: instrumentation_attrs.merge(
                  OpenTelemetry::Common::HTTP::ClientContext.attributes
                ),
                kind: :client
              )

              OpenTelemetry::Trace.with_span(span) do
                OpenTelemetry.propagation.inject(processed_headers)
              end

              span
            end

            def trace_request
              span = create_request_span

              yield(span).tap do |response|
                # Verify return value is a response.
                # If so, add additional attributes.
                if response.is_a?(::RestClient::Response)
                  span.set_attribute('http.response.status_code', response.code)
                  span.status = OpenTelemetry::Trace::Status.error unless HTTP_STATUS_SUCCESS_RANGE.cover?(response.code.to_i)
                end
              end
            rescue ::RestClient::ExceptionWithResponse => e
              span.set_attribute('http.response.status_code', e.http_code)
              span.status = OpenTelemetry::Trace::Status.error unless HTTP_STATUS_SUCCESS_RANGE.cover?(e.http_code.to_i)
              raise e
            ensure
              span.finish
            end

            def tracer
              RestClient::Instrumentation.instance.tracer
            end
          end
        end
      end
    end
  end
end
