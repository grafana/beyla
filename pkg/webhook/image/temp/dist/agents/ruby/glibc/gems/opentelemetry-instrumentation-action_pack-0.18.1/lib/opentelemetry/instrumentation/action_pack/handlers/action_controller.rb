# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActionPack
      module Handlers
        # Action Controller handler to handle the notification from Active Support
        class ActionController
          # @param config [Hash] of instrumentation options
          def initialize(config)
            @config = config
            @span_naming = config.fetch(:span_naming)
          end

          # Invoked by ActiveSupport::Notifications at the start of the instrumentation block
          #
          # @param _name [String] of the event (unused)
          # @param _id [String] of the event (unused)
          # @param payload [Hash] the payload passed as a method argument
          # @return [Hash] the payload passed as a method argument
          def start(_name, _id, payload)
            span = OpenTelemetry::Instrumentation::Rack.current_span
            return unless span.recording?

            request = payload[:request]
            # It seems that there are cases in Rails functional tests where it bypasses the routing system and the `action_dispatch.route_uri_pattern` header not being set.
            # Our Test suite executes the routing system so we are unable to recreate this error case.
            # https://github.com/rails/rails/blob/747f85f200e7bb2c1a31b4e26e5a5655e2dc0cdc/actionpack/lib/action_dispatch/http/request.rb#L160
            http_route = request.route_uri_pattern&.chomp('(.:format)') if request.respond_to?(:route_uri_pattern)

            http_route = "#{request.script_name}#{http_route}" if http_route && !request.script_name.empty?

            attributes = {
              OpenTelemetry::SemanticConventions::Trace::CODE_NAMESPACE => String(payload[:controller]),
              OpenTelemetry::SemanticConventions::Trace::CODE_FUNCTION => String(payload[:action])
            }
            attributes[OpenTelemetry::SemanticConventions::Trace::HTTP_ROUTE] = http_route if http_route

            if request.filtered_path != request.fullpath
              filtered_query = request.filtered_path.split('?', 2)[1]
              attributes['url.query'] = filtered_query if filtered_query
            end

            if @span_naming == :semconv
              span.name = if http_route
                            "#{request.method} #{http_route}"
                          else
                            "#{request.method} /#{payload.dig(:params, :controller)}/#{payload.dig(:params, :action)}"
                          end
            # If there is an exception we want to keep the original span name
            # so it is easier to see where the request was routed to.
            elsif !request.env['action_dispatch.exception']
              span.name = "#{payload[:controller]}##{payload[:action]}"
            end

            span.add_attributes(attributes)
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e)
          end

          # Invoked by ActiveSupport::Notifications at the end of the instrumentation block
          #
          # @param _name [String] of the event (unused)
          # @param _id [String] of the event (unused)
          # @param payload [Hash] the payload passed as a method argument
          # @return [Hash] the payload passed as a method argument
          def finish(_name, _id, payload)
            span = OpenTelemetry::Instrumentation::Rack.current_span
            span.record_exception(payload[:exception_object]) if payload[:exception_object]
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e)
          end
        end
      end
    end
  end
end
