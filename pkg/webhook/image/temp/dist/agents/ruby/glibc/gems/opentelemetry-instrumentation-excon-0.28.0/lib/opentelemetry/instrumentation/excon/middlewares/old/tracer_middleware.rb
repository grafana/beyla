# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Excon
      module Middlewares
        module Old
          # Excon middleware for instrumentation
          class TracerMiddleware < ::Excon::Middleware::Base
            # Constant for the HTTP status range
            HTTP_STATUS_SUCCESS_RANGE = (100..399)

            def request_call(datum)
              return @stack.request_call(datum) if untraced?(datum)

              span_data = HttpHelper.span_attrs_for_old(datum[:method])

              attributes = {
                OpenTelemetry::SemanticConventions::Trace::HTTP_HOST => datum[:host],
                OpenTelemetry::SemanticConventions::Trace::HTTP_SCHEME => datum[:scheme],
                OpenTelemetry::SemanticConventions::Trace::HTTP_TARGET => datum[:path],
                OpenTelemetry::SemanticConventions::Trace::HTTP_URL => OpenTelemetry::Common::Utilities.cleanse_url(::Excon::Utils.request_uri(datum)),
                OpenTelemetry::SemanticConventions::Trace::NET_PEER_NAME => datum[:hostname],
                OpenTelemetry::SemanticConventions::Trace::NET_PEER_PORT => datum[:port]
              }
              peer_service = Excon::Instrumentation.instance.config[:peer_service]
              attributes[OpenTelemetry::SemanticConventions::Trace::PEER_SERVICE] = peer_service if peer_service
              attributes.merge!(span_data.attributes)
              span = tracer.start_span(span_data.span_name, attributes: attributes, kind: :client)
              ctx = OpenTelemetry::Trace.context_with_span(span)
              datum[:otel_span] = span
              datum[:otel_token] = OpenTelemetry::Context.attach(ctx)
              OpenTelemetry.propagation.inject(datum[:headers])
              @stack.request_call(datum)
            end

            def response_call(datum)
              @stack.response_call(datum).tap do |d|
                handle_response(d)
              end
            end

            def error_call(datum)
              handle_response(datum)
              @stack.error_call(datum)
            end

            # Returns a copy of the default stack with the trace middleware injected
            def self.around_default_stack
              ::Excon.defaults[:middlewares].dup.tap do |default_stack|
                # If the default stack contains a version of the trace middleware already...
                existing_trace_middleware = default_stack.find { |m| m <= TracerMiddleware }
                default_stack.delete(existing_trace_middleware) if existing_trace_middleware
                # Inject after the ResponseParser middleware
                response_middleware_index = default_stack.index(::Excon::Middleware::ResponseParser).to_i
                default_stack.insert(response_middleware_index + 1, self)
              end
            end

            private

            def handle_response(datum)
              datum.delete(:otel_span)&.tap do |span|
                token = datum.delete(:otel_token)
                OpenTelemetry::Context.detach(token) if token
                return unless span.recording?

                if datum.key?(:response)
                  response = datum[:response]
                  span.set_attribute(OpenTelemetry::SemanticConventions::Trace::HTTP_STATUS_CODE, response[:status])
                  span.status = OpenTelemetry::Trace::Status.error unless HTTP_STATUS_SUCCESS_RANGE.cover?(response[:status].to_i)
                end

                if datum.key?(:error)
                  span.status = OpenTelemetry::Trace::Status.error('Request has failed')
                  span.record_exception(datum[:error])
                end

                span.finish
              end
            rescue StandardError => e
              OpenTelemetry.handle_error(e)
            end

            def tracer
              Excon::Instrumentation.instance.tracer
            end

            def untraced?(datum)
              datum.key?(:otel_span) || Excon::Instrumentation.instance.untraced?(datum[:host])
            end
          end
        end
      end
    end
  end
end
