# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module HttpClient
      # The Instrumentation class contains logic to detect and install the HttpClient instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          patch_type = determine_semconv
          send(:"require_dependencies_#{patch_type}")
          send(:"patch_#{patch_type}")
        end

        present do
          defined?(::HTTPClient)
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

        def patch_dup
          ::HTTPClient.prepend(Patches::Dup::Client)
          ::HTTPClient::Session.prepend(Patches::Dup::Session)
        end

        def patch_old
          ::HTTPClient.prepend(Patches::Old::Client)
          ::HTTPClient::Session.prepend(Patches::Old::Session)
        end

        def patch_stable
          ::HTTPClient.prepend(Patches::Stable::Client)
          ::HTTPClient::Session.prepend(Patches::Stable::Session)
        end

        def require_dependencies_dup
          require_relative 'patches/dup/client'
          require_relative 'patches/dup/session'
        end

        def require_dependencies_old
          require_relative 'patches/old/client'
          require_relative 'patches/old/session'
        end

        def require_dependencies_stable
          require_relative 'patches/stable/client'
          require_relative 'patches/stable/session'
        end
      end
    end
  end
end
