# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Faraday
      module Middlewares
        module Dup
          # TracerMiddleware propagates context and instruments Faraday requests
          # by way of its middleware system
          class TracerMiddleware < ::Faraday::Middleware
            # Constant for the HTTP status range
            HTTP_STATUS_SUCCESS_RANGE = (100..399)

            def call(env)
              span_data = HttpHelper.span_attrs_for_dup(env.method)

              config = Faraday::Instrumentation.instance.config

              attributes = span_creation_attributes(url: env.url, config: config)
              attributes.merge!(span_data.attributes)

              OpenTelemetry::Common::HTTP::ClientContext.with_attributes(attributes) do |attrs, _|
                tracer.in_span(
                  span_data.span_name, attributes: attrs, kind: config.fetch(:span_kind)
                ) do |span|
                  OpenTelemetry.propagation.inject(env.request_headers)

                  if config[:enable_internal_instrumentation] == false
                    OpenTelemetry::Common::Utilities.untraced do
                      app.call(env).on_complete { |resp| trace_response(span, resp.status) }
                    end
                  else
                    app.call(env).on_complete { |resp| trace_response(span, resp.status) }
                  end
                rescue ::Faraday::Error => e
                  trace_response(span, e.response[:status]) if e.response

                  raise
                end
              end
            end

            private

            def span_creation_attributes(url:, config:)
              cleansed_url = OpenTelemetry::Common::Utilities.cleanse_url(url.to_s)
              attrs = {
                'http.url' => cleansed_url,
                'url.full' => cleansed_url,
                'faraday.adapter.name' => app.class.name
              }
              if url.host
                attrs['net.peer.name'] = url.host
                attrs['server.address'] = url.host
              end
              attrs['peer.service'] = config[:peer_service] if config[:peer_service]

              attrs
            end

            # Versions prior to 1.0 do not define an accessor for app
            attr_reader :app if Gem::Version.new(Faraday::VERSION) < Gem::Version.new('1.0.0')

            def tracer
              Faraday::Instrumentation.instance.tracer
            end

            def trace_response(span, status)
              span.set_attribute('http.status_code', status)
              span.set_attribute('http.response.status_code', status)
              span.status = OpenTelemetry::Trace::Status.error unless HTTP_STATUS_SUCCESS_RANGE.cover?(status.to_i)
            end
          end
        end
      end
    end
  end
end
