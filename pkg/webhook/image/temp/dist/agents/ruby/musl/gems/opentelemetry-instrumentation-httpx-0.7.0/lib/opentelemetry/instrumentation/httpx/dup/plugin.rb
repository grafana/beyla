# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module HTTPX
      module Dup
        # Dup Plugin
        module Plugin
          def self.load_dependencies(klass)
            require_relative '../plugin'
            klass.plugin(HTTPX::Plugin)

            HTTPX::Plugin.const_set(:RequestTracer, RequestTracer)
          end
        end

        # Instruments around HTTPX's request/response lifecycle in order to generate
        # an OTEL trace.
        module RequestTracer
          extend self

          # initializes tracing on the +request+.
          def call(request)
            span = nil

            # request objects are reused, when already buffered requests get rerouted to a different
            # connection due to connection issues, or when they already got a response, but need to
            # be retried. In such situations, the original span needs to be extended for the former,
            # while a new is required for the latter.
            request.on(:idle) do
              span = nil
            end
            # the span is initialized when the request is buffered in the parser, which is the closest
            # one gets to actually sending the request.
            request.on(:headers) do
              next if span

              span = initialize_span(request)
            end

            request.on(:response) do |response|
              span = initialize_span(request, request.init_time) if !span && request.init_time

              finish(response, span)
            end
          end

          private

          def finish(response, span)
            if response.is_a?(::HTTPX::ErrorResponse)
              span.record_exception(response.error)
              span.status = Trace::Status.error(response.error.to_s)
            else
              span.set_attribute(OpenTelemetry::SemanticConventions::Trace::HTTP_STATUS_CODE, response.status)
              span.set_attribute('http.response.status_code', response.status)

              if response.status.between?(400, 599)
                err = ::HTTPX::HTTPError.new(response)
                span.record_exception(err)
                span.status = Trace::Status.error(err.to_s)
              end
            end

            span.finish
          end

          # return a span initialized with the +@request+ state.
          def initialize_span(request, start_time = ::Time.now)
            verb = request.verb
            uri = request.uri

            span_data = HttpHelper.span_attrs_for_dup(verb)

            config = HTTPX::Instrumentation.instance.config

            attributes = {
              OpenTelemetry::SemanticConventions::Trace::HTTP_HOST => uri.host,
              OpenTelemetry::SemanticConventions::Trace::HTTP_SCHEME => uri.scheme,
              OpenTelemetry::SemanticConventions::Trace::HTTP_TARGET => uri.path,
              OpenTelemetry::SemanticConventions::Trace::HTTP_URL => "#{uri.scheme}://#{uri.host}",
              OpenTelemetry::SemanticConventions::Trace::NET_PEER_NAME => uri.host,
              OpenTelemetry::SemanticConventions::Trace::NET_PEER_PORT => uri.port,
              'url.scheme' => uri.scheme,
              'url.path' => uri.path,
              'url.full' => "#{uri.scheme}://#{uri.host}",
              'server.address' => uri.host,
              'server.port' => uri.port
            }

            attributes['url.query'] = uri.query unless uri.query.nil?
            attributes[OpenTelemetry::SemanticConventions::Trace::PEER_SERVICE] = config[:peer_service] if config[:peer_service]
            attributes.merge!(span_data.attributes)

            span = tracer.start_span(span_data.span_name, attributes: attributes, kind: :client, start_timestamp: start_time)

            OpenTelemetry::Trace.with_span(span) do
              OpenTelemetry.propagation.inject(request.headers)
            end

            span
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e)
          end

          def tracer
            HTTPX::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
