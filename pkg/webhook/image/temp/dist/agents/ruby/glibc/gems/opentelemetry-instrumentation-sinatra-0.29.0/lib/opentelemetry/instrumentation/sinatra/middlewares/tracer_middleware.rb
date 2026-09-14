# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0
require 'opentelemetry-instrumentation-rack'

module OpenTelemetry
  module Instrumentation
    module Sinatra
      module Middlewares
        # Middleware to trace Sinatra requests
        class TracerMiddleware
          def initialize(app)
            @app = app
          end

          def call(env)
            response = @app.call(env)
          ensure
            trace_response(env, response)
          end

          def trace_response(env, response)
            span = OpenTelemetry::Instrumentation::Rack.current_span
            return unless span.recording?

            span.set_attribute('http.route', env['sinatra.route'].split.last) if env['sinatra.route']
            span.name = env['sinatra.route'] if env['sinatra.route']

            return if response.nil?

            sinatra_response = ::Sinatra::Response.new([], response.first)
            return unless sinatra_response.server_error?

            span.record_exception(env['sinatra.error']) if env['sinatra.error']
            span.status = OpenTelemetry::Trace::Status.error
          end
        end
      end
    end
  end
end
