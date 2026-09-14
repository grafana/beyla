# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module Rack
      # The Instrumentation class contains logic to detect and install the Rack
      # instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          patch_type = determine_semconv
          send(:"require_dependencies_#{patch_type}")
        end

        present do
          defined?(::Rack)
        end

        option :allowed_request_headers,  default: [],    validate: :array
        option :allowed_response_headers, default: [],    validate: :array
        option :application,              default: nil,   validate: :callable
        option :record_frontend_span,     default: false, validate: :boolean
        option :untraced_endpoints,       default: [],    validate: :array
        option :url_quantization,         default: nil,   validate: :callable
        option :untraced_requests,        default: nil,   validate: :callable
        option :response_propagators,     default: [],    validate: :array
        # This option is only valid for applications using Rack 2.0 or greater
        option :use_rack_events,          default: true, validate: :boolean

        def middleware_args
          patch_type = determine_semconv
          send(:"middleware_args_#{patch_type}")
        end

        # Temporary Helper for Sinatra and ActionPack middleware to use during installation
        #
        # @example Default usage
        #   Rack::Builder.new do
        #     use *OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.middleware_args
        #     run lambda { |_arg| [200, { 'Content-Type' => 'text/plain' }, body] }
        #   end
        # @return [Array] consisting of a middleware and arguments used in rack builders
        def middleware_args_old
          if config.fetch(:use_rack_events, false) == true && defined?(OpenTelemetry::Instrumentation::Rack::Middlewares::Old::EventHandler)
            [::Rack::Events, [OpenTelemetry::Instrumentation::Rack::Middlewares::Old::EventHandler.new]]
          else
            [OpenTelemetry::Instrumentation::Rack::Middlewares::Old::TracerMiddleware]
          end
        end

        def middleware_args_dup
          if config.fetch(:use_rack_events, false) == true && defined?(OpenTelemetry::Instrumentation::Rack::Middlewares::Dup::EventHandler)
            [::Rack::Events, [OpenTelemetry::Instrumentation::Rack::Middlewares::Dup::EventHandler.new]]
          else
            [OpenTelemetry::Instrumentation::Rack::Middlewares::Dup::TracerMiddleware]
          end
        end

        def middleware_args_stable
          if config.fetch(:use_rack_events, false) == true && defined?(OpenTelemetry::Instrumentation::Rack::Middlewares::Stable::EventHandler)
            [::Rack::Events, [OpenTelemetry::Instrumentation::Rack::Middlewares::Stable::EventHandler.new]]
          else
            [OpenTelemetry::Instrumentation::Rack::Middlewares::Stable::TracerMiddleware]
          end
        end

        private

        def determine_semconv
          stability_opt_in = ENV.fetch('OTEL_SEMCONV_STABILITY_OPT_IN', '')
          values = stability_opt_in.split(',').map(&:strip)

          if values.include?('http/dup')
            emit_old_semconv_deprecation_warning('http/dup')
            'dup'
          elsif values.include?('old')
            emit_old_semconv_deprecation_warning('old')
            'old'
          else
            'stable'
          end
        end

        def emit_old_semconv_deprecation_warning(option)
          OpenTelemetry.logger.warn("The `#{option}` option for OTEL_SEMCONV_STABILITY_OPT_IN is deprecated and will be removed on April 15, 2026. Please migrate to the stable HTTP semantic conventions.")
        end

        def require_dependencies_old
          require_relative 'middlewares/old/event_handler' if defined?(::Rack::Events)
          require_relative 'middlewares/old/tracer_middleware'
        end

        def require_dependencies_stable
          require_relative 'middlewares/stable/event_handler' if defined?(::Rack::Events)
          require_relative 'middlewares/stable/tracer_middleware'
        end

        def require_dependencies_dup
          require_relative 'middlewares/dup/event_handler' if defined?(::Rack::Events)
          require_relative 'middlewares/dup/tracer_middleware'
        end

        def config_options(user_config)
          config = super
          config[:allowed_rack_request_headers] = config[:allowed_request_headers].compact.each_with_object({}) do |header, memo|
            key = header.to_s.upcase.gsub(/[-\s]/, '_')
            case key
            when 'CONTENT_TYPE', 'CONTENT_LENGTH'
              memo[key] = build_attribute_name('http.request.header.', header)
            else
              memo["HTTP_#{key}"] = build_attribute_name('http.request.header.', header)
            end
          end

          config[:allowed_rack_response_headers] = config[:allowed_response_headers].each_with_object({}) do |header, memo|
            memo[header] = build_attribute_name('http.response.header.', header)
            memo[header.to_s.upcase] = build_attribute_name('http.response.header.', header)
          end

          config[:untraced_endpoints]&.compact!
          config
        end

        def build_attribute_name(prefix, suffix)
          prefix + suffix.to_s.downcase.gsub(/[-\s]/, '_')
        end
      end
    end
  end
end
