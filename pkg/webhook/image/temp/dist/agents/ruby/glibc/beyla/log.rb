# frozen_string_literal: true

require_relative 'log_prefix'

module Beyla
  module OpenTelemetry
    module Log
      module_function

      def warning(message)
        Kernel.warn "#{PREFIX} #{message}"
      end

      def debug(message)
        return unless ENV['OTEL_INJECTOR_LOG_LEVEL'] == 'debug'

        Kernel.warn "#{PREFIX} #{message}"
      end
    end
  end
end
