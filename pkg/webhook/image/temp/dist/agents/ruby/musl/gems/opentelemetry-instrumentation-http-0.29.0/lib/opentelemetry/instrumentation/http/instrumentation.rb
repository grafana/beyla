# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module HTTP
      # The Instrumentation class contains logic to detect and install the Http instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          patch_type = determine_semconv
          send(:"require_dependencies_#{patch_type}")
          send(:"patch_#{patch_type}")
        end

        present do
          !(defined?(::HTTP::Client).nil? || defined?(::HTTP::Connection).nil?)
        end

        option :span_name_formatter, default: nil, validate: :callable

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
          ::HTTP::Client.prepend(Patches::Old::Client)
          ::HTTP::Connection.prepend(Patches::Old::Connection)
        end

        def patch_dup
          ::HTTP::Client.prepend(Patches::Dup::Client)
          ::HTTP::Connection.prepend(Patches::Dup::Connection)
        end

        def patch_stable
          ::HTTP::Client.prepend(Patches::Stable::Client)
          ::HTTP::Connection.prepend(Patches::Stable::Connection)
        end

        def require_dependencies_dup
          require_relative 'patches/dup/client'
          require_relative 'patches/dup/connection'
        end

        def require_dependencies_old
          require_relative 'patches/old/client'
          require_relative 'patches/old/connection'
        end

        def require_dependencies_stable
          require_relative 'patches/stable/client'
          require_relative 'patches/stable/connection'
        end
      end
    end
  end
end
