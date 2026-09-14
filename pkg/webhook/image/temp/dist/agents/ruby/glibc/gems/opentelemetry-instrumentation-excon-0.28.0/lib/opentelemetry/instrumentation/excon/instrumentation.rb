# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative '../concerns/untraced_hosts'

module OpenTelemetry
  module Instrumentation
    module Excon
      # The Instrumentation class contains logic to detect and install the Excon
      # instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        include OpenTelemetry::Instrumentation::Concerns::UntracedHosts

        install do |_config|
          patch_type = determine_semconv
          send(:"require_dependencies_#{patch_type}")
          send(:"add_middleware_#{patch_type}")
          send(:"patch_#{patch_type}")
        end

        present do
          defined?(::Excon)
        end

        option :peer_service, default: nil, validate: :string

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

        def require_dependencies_dup
          require_relative 'middlewares/dup/tracer_middleware'
          require_relative 'patches/dup/socket'
        end

        def require_dependencies_stable
          require_relative 'middlewares/stable/tracer_middleware'
          require_relative 'patches/stable/socket'
        end

        def require_dependencies_old
          require_relative 'middlewares/old/tracer_middleware'
          require_relative 'patches/old/socket'
        end

        def add_middleware_dup
          ::Excon.defaults[:middlewares] = Middlewares::Dup::TracerMiddleware.around_default_stack
        end

        def add_middleware_stable
          ::Excon.defaults[:middlewares] = Middlewares::Stable::TracerMiddleware.around_default_stack
        end

        def add_middleware_old
          ::Excon.defaults[:middlewares] = Middlewares::Old::TracerMiddleware.around_default_stack
        end

        def patch_dup
          ::Excon::Socket.prepend(Patches::Dup::Socket)
        end

        def patch_stable
          ::Excon::Socket.prepend(Patches::Stable::Socket)
        end

        def patch_old
          ::Excon::Socket.prepend(Patches::Old::Socket)
        end
      end
    end
  end
end
