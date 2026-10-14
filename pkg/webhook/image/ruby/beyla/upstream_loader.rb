# frozen_string_literal: true

module Beyla
  module OpenTelemetry
    class UpstreamLoader
      def initialize(bundle_root)
        @bundle_root = bundle_root
      end

      def call(check)
        add_load_paths(check.load_paths)
        with_exclusions(check.exclusions) { Kernel.require(upstream_entrypoint) }
      end

      private

      def add_load_paths(paths)
        paths.reverse_each { |path| $LOAD_PATH.unshift(path) unless $LOAD_PATH.include?(path) }
      end

      def upstream_entrypoint
        pattern = File.join(
          @bundle_root, 'gems', 'opentelemetry-auto-instrumentation-*',
          'lib', 'opentelemetry-auto-instrumentation.rb'
        )
        matches = Dir.glob(pattern)
        raise LoadError, 'upstream entrypoint not found' unless matches.one?

        matches.first
      end

      def with_exclusions(exclusions)
        previous = ENV['DISALLOWED_LIB_PATH']
        ENV['DISALLOWED_LIB_PATH'] = exclusions.join(',')
        yield
      ensure
        previous.nil? ? ENV.delete('DISALLOWED_LIB_PATH') : ENV['DISALLOWED_LIB_PATH'] = previous
      end
    end
  end
end
