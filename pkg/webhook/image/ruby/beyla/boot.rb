# frozen_string_literal: true

require_relative 'bundle_lock'
require_relative 'dependency_compatibility_checker'
require_relative 'log'
require_relative 'open_telemetry_guard'
require_relative 'protocol_guard'
require_relative 'rails_guard'
require_relative 'upstream_loader'

module Beyla
  module OpenTelemetry
    class Boot
      def self.run(bundle_root, entrypoint)
        new(bundle_root, entrypoint).run
      end

      def initialize(bundle_root, entrypoint)
        @bundle_root = bundle_root
        @entrypoint = entrypoint
      end

      def run
        snapshot = BundleLock.load
        reason = rejection(snapshot)
        return Log.warning(reason) if reason

        deps = DependencyCompatibilityChecker.new(snapshot, @bundle_root).check_dependencies
        return Log.warning(deps.rejection) if deps.rejection

        UpstreamLoader.new(@bundle_root).call(deps)
      rescue StandardError, ScriptError => e
        Log.warning("initialization failed: #{e.message}")
      end

      private

      def rejection(snapshot)
        ProtocolGuard.rejection(ENV) ||
          OpenTelemetryGuard.rejection(snapshot, ENV['RUBYOPT'], @entrypoint) ||
          RailsGuard.rejection(snapshot)
      end
    end
  end
end
