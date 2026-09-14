# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module HTTPX
      # The Instrumentation class contains logic to detect and install the Http instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          patch_type = determine_semconv
          send(:"require_dependencies_#{patch_type}")
          send(:"patch_#{patch_type}")
        end

        compatible do
          Gem::Version.new(::HTTPX::VERSION) >= Gem::Version.new('1.6.0')
        end

        present do
          defined?(::HTTPX)
        end

        option :peer_service, default: nil, validate: :string

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

        def patch_old
          otel_session = ::HTTPX.plugin(Old::Plugin)

          ::HTTPX.send(:remove_const, :Session)
          ::HTTPX.send(:const_set, :Session, otel_session.class)
        end

        def patch_stable
          otel_session = ::HTTPX.plugin(Stable::Plugin)

          ::HTTPX.send(:remove_const, :Session)
          ::HTTPX.send(:const_set, :Session, otel_session.class)
        end

        def patch_dup
          otel_session = ::HTTPX.plugin(Dup::Plugin)

          ::HTTPX.send(:remove_const, :Session)
          ::HTTPX.send(:const_set, :Session, otel_session.class)
        end

        def require_dependencies_old
          require_relative 'old/plugin'
        end

        def require_dependencies_stable
          require_relative 'stable/plugin'
        end

        def require_dependencies_dup
          require_relative 'dup/plugin'
        end
      end
    end
  end
end
