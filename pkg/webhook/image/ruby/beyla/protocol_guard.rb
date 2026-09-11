# frozen_string_literal: true

module Beyla
  module OpenTelemetry
    module ProtocolGuard
      SIGNALS = %w[TRACES METRICS LOGS].freeze
      REQUIRED_PROTOCOL = 'http/protobuf'

      module_function

      def rejection(env)
        invalid = SIGNALS.filter_map do |signal|
          next unless otlp_enabled?(env, signal)

          protocol = effective_protocol(env, signal)
          signal.downcase unless protocol == REQUIRED_PROTOCOL
        end
        return if invalid.empty?

        "#{REQUIRED_PROTOCOL} is required for enabled OTLP signals: #{invalid.join(', ')}"
      end

      def otlp_enabled?(env, signal)
        value = env.fetch("OTEL_#{signal}_EXPORTER", 'otlp')
        value = 'otlp' if value.strip.empty?
        value.split(',').any? { |exporter| exporter.strip.downcase == 'otlp' }
      end

      def effective_protocol(env, signal)
        specific = env.fetch("OTEL_EXPORTER_OTLP_#{signal}_PROTOCOL", '').strip
        shared = env.fetch('OTEL_EXPORTER_OTLP_PROTOCOL', '').strip
        (specific.empty? ? shared : specific).then { |value| value.empty? ? REQUIRED_PROTOCOL : value.downcase }
      end
    end
  end
end
