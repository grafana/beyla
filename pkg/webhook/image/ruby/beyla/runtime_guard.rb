# frozen_string_literal: true

require_relative 'compatibility'

module Beyla
  module OpenTelemetry
    module RuntimeGuard
      module_function

      def disabled?(env)
        env.fetch('OTEL_SDK_DISABLED', '').downcase == 'true'
      end

      def rejection(engine, version)
        return "#{engine} is not supported; CRuby is required" unless engine == 'ruby'
        return unless version_less_than?(version, Compatibility::MINIMUM_RUBY_VERSION)

        "Ruby #{version} is not supported; Ruby #{Compatibility::MINIMUM_RUBY_VERSION} or newer is required"
      end

      def version_less_than?(actual, minimum)
        (version_pair(actual) <=> version_pair(minimum)) == -1
      end

      def version_pair(version)
        version.split('.').first(2).map { |part| part.to_i }
      end
    end
  end
end
