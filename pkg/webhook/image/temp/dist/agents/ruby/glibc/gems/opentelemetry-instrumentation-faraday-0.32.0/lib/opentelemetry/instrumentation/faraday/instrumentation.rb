# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Faraday
      # The Instrumentation class contains logic to detect and install the Faraday
      # instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('1.0')

        install do |_config|
          patch_type = determine_semconv
          send(:"require_dependencies_#{patch_type}")
          send(:"register_tracer_middleware_#{patch_type}")
          send(:"use_middleware_by_default_#{patch_type}")
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        present do
          defined?(::Faraday)
        end

        option :span_kind, default: :client, validate: %i[client internal]
        option :peer_service, default: nil, validate: :string
        option :enable_internal_instrumentation, default: false, validate: :boolean

        private

        def gem_version
          Gem::Version.new(::Faraday::VERSION)
        end

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

        def require_dependencies_dup
          require_relative 'middlewares/dup/tracer_middleware'
          require_relative 'patches/dup/connection'
        end

        def require_dependencies_old
          require_relative 'middlewares/old/tracer_middleware'
          require_relative 'patches/old/connection'
        end

        def require_dependencies_stable
          require_relative 'middlewares/stable/tracer_middleware'
          require_relative 'patches/stable/connection'
        end

        def register_tracer_middleware_dup
          ::Faraday::Middleware.register_middleware(
            open_telemetry: Middlewares::Dup::TracerMiddleware
          )
        end

        def register_tracer_middleware_old
          ::Faraday::Middleware.register_middleware(
            open_telemetry: Middlewares::Old::TracerMiddleware
          )
        end

        def register_tracer_middleware_stable
          ::Faraday::Middleware.register_middleware(
            open_telemetry: Middlewares::Stable::TracerMiddleware
          )
        end

        def use_middleware_by_default_dup
          ::Faraday::Connection.prepend(Patches::Dup::Connection)
        end

        def use_middleware_by_default_old
          ::Faraday::Connection.prepend(Patches::Old::Connection)
        end

        def use_middleware_by_default_stable
          ::Faraday::Connection.prepend(Patches::Stable::Connection)
        end
      end
    end
  end
end
