# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/trace/status'

module OpenTelemetry
  module Instrumentation
    module Rack
      module Middlewares
        module Dup
          # TracerMiddleware propagates context and instruments Rack requests
          # by way of its middleware system
          class TracerMiddleware
            class << self
              def allowed_rack_request_headers
                @allowed_rack_request_headers ||= Array(config[:allowed_request_headers]).each_with_object({}) do |header, memo|
                  key = header.to_s.upcase.gsub(/[-\s]/, '_')
                  case key
                  when 'CONTENT_TYPE', 'CONTENT_LENGTH'
                    memo[key] = build_attribute_name('http.request.header.', header)
                  else
                    memo["HTTP_#{key}"] = build_attribute_name('http.request.header.', header)
                  end
                end
              end

              def allowed_response_headers
                @allowed_response_headers ||= Array(config[:allowed_response_headers]).each_with_object({}) do |header, memo|
                  memo[header] = build_attribute_name('http.response.header.', header)
                  memo[header.to_s.upcase] = build_attribute_name('http.response.header.', header)
                end
              end

              def build_attribute_name(prefix, suffix)
                prefix + suffix.to_s.downcase.gsub(/[-\s]/, '_')
              end

              def config
                Rack::Instrumentation.instance.config
              end

              private

              def clear_cached_config
                @allowed_rack_request_headers = nil
                @allowed_response_headers = nil
              end
            end

            EMPTY_HASH = {}.freeze

            def initialize(app)
              @app = app
              @untraced_endpoints = config[:untraced_endpoints]
            end

            def call(env)
              if untraced_request?(env)
                OpenTelemetry::Common::Utilities.untraced do
                  return @app.call(env)
                end
              end

              original_env = env.dup
              extracted_context = OpenTelemetry.propagation.extract(
                env,
                getter: OpenTelemetry::Common::Propagation.rack_env_getter
              )
              frontend_context = create_frontend_span(env, extracted_context)

              # restore extracted context in this process:
              OpenTelemetry::Context.with_current(frontend_context || extracted_context) do
                request_span_name = create_request_span_name(env['REQUEST_URI'] || original_env['PATH_INFO'], env)
                request_span_kind = frontend_context.nil? ? :server : :internal
                tracer.in_span(request_span_name,
                               attributes: request_span_attributes(env: env),
                               kind: request_span_kind) do |request_span|
                  request_start_time = OpenTelemetry::Instrumentation::Rack::Util::QueueTime.get_request_start(env)
                  request_span.add_event('http.proxy.request.started', timestamp: request_start_time) unless request_start_time.nil?
                  OpenTelemetry::Instrumentation::Rack.with_span(request_span) do
                    @app.call(env).tap do |status, headers, response|
                      set_attributes_after_request(request_span, status, headers, response)
                      config[:response_propagators].each { |propagator| propagator.inject(headers) }
                    end
                  end
                end
              end
            ensure
              finish_span(frontend_context)
            end

            private

            def untraced_request?(env)
              return true if @untraced_endpoints.include?(env['PATH_INFO'])
              return true if config[:untraced_requests]&.call(env)

              false
            end

            # return Context with the frontend span as the current span
            def create_frontend_span(env, extracted_context)
              request_start_time = OpenTelemetry::Instrumentation::Rack::Util::QueueTime.get_request_start(env)

              return unless config[:record_frontend_span] && !request_start_time.nil?

              span = tracer.start_span('http_server.proxy',
                                       with_parent: extracted_context,
                                       start_timestamp: request_start_time,
                                       kind: :server)

              OpenTelemetry::Trace.context_with_span(span, parent_context: extracted_context)
            end

            def finish_span(context)
              OpenTelemetry::Trace.current_span(context).finish if context
            end

            def tracer
              OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.tracer
            end

            def request_span_attributes(env:)
              attributes = {
                'http.method' => env['REQUEST_METHOD'],
                'http.host' => env['HTTP_HOST'] || 'unknown',
                'server.address' => env['HTTP_HOST'] || 'unknown',
                'http.scheme' => env['rack.url_scheme'],
                'http.target' => env['QUERY_STRING'].empty? ? env['PATH_INFO'] : "#{env['PATH_INFO']}?#{env['QUERY_STRING']}",
                'http.request.method' => env['REQUEST_METHOD'],
                'url.scheme' => env['rack.url_scheme'],
                'url.path' => env['PATH_INFO']
              }

              attributes['url.query'] = env['QUERY_STRING'] unless env['QUERY_STRING'].empty?
              if env['HTTP_USER_AGENT']
                attributes['http.user_agent'] = env['HTTP_USER_AGENT']
                attributes['user_agent.original'] = env['HTTP_USER_AGENT']
              end
              attributes.merge!(allowed_request_headers(env))
            end

            # https://github.com/open-telemetry/opentelemetry-specification/blob/master/specification/data-http.md#name
            #
            # recommendation: span.name(s) should be low-cardinality (e.g.,
            # strip off query param value, keep param name)
            #
            # see http://github.com/open-telemetry/opentelemetry-specification/pull/416/files
            def create_request_span_name(request_uri_or_path_info, env)
              # NOTE: dd-trace-rb has implemented 'quantization' (which lowers url cardinality)
              #       see Datadog::Quantization::HTTP.url

              if (implementation = config[:url_quantization])
                implementation.call(request_uri_or_path_info, env)
              else
                env['REQUEST_METHOD']
              end
            end

            def set_attributes_after_request(span, status, headers, _response)
              span.status = OpenTelemetry::Trace::Status.error if (500..599).cover?(status.to_i)
              span.set_attribute('http.status_code', status)
              span.set_attribute('http.response.status_code', status)

              # NOTE: if data is available, it would be good to do this:
              # set_attribute('http.route', ...
              # e.g., "/users/:userID?

              allowed_response_headers(headers).each { |k, v| span.set_attribute(k, v) }
            end

            def allowed_request_headers(env)
              return EMPTY_HASH if self.class.allowed_rack_request_headers.empty?

              {}.tap do |result|
                self.class.allowed_rack_request_headers.each do |key, value|
                  result[value] = env[key] if env.key?(key)
                end
              end
            end

            def allowed_response_headers(headers)
              return EMPTY_HASH if headers.nil?
              return EMPTY_HASH if self.class.allowed_response_headers.empty?

              {}.tap do |result|
                self.class.allowed_response_headers.each do |key, value|
                  if headers.key?(key)
                    result[value] = headers[key]
                  else
                    # do case-insensitive match:
                    headers.each do |k, v|
                      if k.upcase == key
                        result[value] = v
                        break
                      end
                    end
                  end
                end
              end
            end

            def config
              Rack::Instrumentation.instance.config
            end
          end
        end
      end
    end
  end
end
