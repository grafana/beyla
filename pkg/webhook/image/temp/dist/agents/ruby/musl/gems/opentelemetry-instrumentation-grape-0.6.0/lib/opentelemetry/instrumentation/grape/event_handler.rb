# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Grape
      # Handles the events instrumented with ActiveSupport notifications.
      # These handlers contain all the logic needed to create and connect spans.
      class EventHandler
        class << self
          # Handles the start of the endpoint_run event, modifying the parent Rack span
          # and recording it as a span event
          def endpoint_run(_name, start, _finish, _id, payload)
            span = OpenTelemetry::Instrumentation::Rack.current_span
            return unless span.recording?

            endpoint = payload[:endpoint]
            span.name = span_name(endpoint)
            span.add_attributes(attributes_from_grape_endpoint(endpoint))

            span.add_event('grape.endpoint_run', timestamp: start)
            handle_payload_exception(span, payload[:exception_object]) if payload[:exception_object]
          end

          # Handles the endpoint_render event, recording it as a span event
          def endpoint_render(_name, start, _finish, _id, payload)
            span = OpenTelemetry::Instrumentation::Rack.current_span
            return unless span.recording?

            span.add_event('grape.endpoint_render', timestamp: start)
          end

          # Handles the endpoint_run_filters events, recording them as a span event
          def endpoint_run_filters(_name, start, finish, _id, payload)
            span = OpenTelemetry::Instrumentation::Rack.current_span
            return unless span.recording?

            filters = payload[:filters]
            type = payload[:type]

            # Prevent submitting empty filters
            return if (!filters || filters.empty?) || !type || (finish - start).zero?

            attributes = { 'grape.filter.type' => type.to_s }
            span.add_event('grape.endpoint_run_filters', attributes: attributes, timestamp: start)
          end

          # Handles the format_response event, recording it as a span event
          def format_response(_name, start, _finish, _id, payload)
            span = OpenTelemetry::Instrumentation::Rack.current_span
            return unless span.recording?

            attributes = {
              'grape.formatter.type' => formatter_type(payload[:formatter])
            }
            span.add_event('grape.format_response', attributes: attributes, timestamp: start)
            handle_payload_exception(span, payload[:exception_object]) if payload[:exception_object]
          end

          private

          def span_name(endpoint)
            "#{request_method(endpoint)} #{path(endpoint)}"
          end

          def attributes_from_grape_endpoint(endpoint)
            {
              OpenTelemetry::SemanticConventions::Trace::CODE_NAMESPACE => endpoint.options[:for]&.instance_variable_get(:@base)&.to_s,
              OpenTelemetry::SemanticConventions::Trace::HTTP_ROUTE => path(endpoint)
            }
          end

          # ActiveSupport::Notifications will attach a `:exception_object` to the payload if there was
          # an error raised during the execution of the &block associated to the Notification.
          def handle_payload_exception(span, exception)
            # Only record exceptions if they were not raised (i.e. do not have a status code in Grape)
            # or do not have a 5xx status code. These exceptions are recorded by Rack.
            # See instrumentation/rack/lib/opentelemetry/instrumentation/rack/middlewares/tracer_middleware.rb#L155
            return unless exception.respond_to?(:status) && ::Rack::Utils.status_code(exception.status) < 500

            span.record_exception(exception)
            span.status = OpenTelemetry::Trace::Status.error("Unhandled exception of type: #{exception.class}")
          end

          def request_method(endpoint)
            endpoint.options[:method]&.first
          end

          def path(endpoint)
            return '' unless endpoint.routes

            namespace = endpoint.routes.first.namespace
            version = endpoint.routes.first.options[:version]&.to_s
            prefix = endpoint.routes.first.options[:prefix]&.to_s
            parts = [prefix, version] + namespace.split('/') + endpoint.options[:path]
            parts.reject { |p| p.nil? || p.empty? || p.eql?('/') }.join('/').prepend('/')
          end

          def formatter_type(formatter)
            return 'custom' unless built_in_grape_formatter?(formatter)

            basename = formatter.name.split('::').last
            # Convert from CamelCase to snake_case
            basename.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
          end

          def built_in_grape_formatter?(formatter)
            formatter.respond_to?(:name) && formatter.name.include?('Grape::Formatter')
          end
        end
      end
    end
  end
end
