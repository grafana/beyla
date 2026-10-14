# frozen_string_literal: true

require 'rubygems'
require_relative 'compatibility'

module Beyla
  module OpenTelemetry
    module RailsGuard
      RAILS_GEMS = %w[rails railties].freeze

      module_function

      def rejection(snapshot, loaded_specs = Gem.loaded_specs)
        versions = detected_versions(snapshot, loaded_specs)
        return if versions.empty?
        return 'Rails is detected but its version cannot be determined' unless versions.one?

        version = Gem::Version.new(versions.first)
        minimum = Gem::Version.new(Compatibility::MINIMUM_RAILS_VERSION)
        return unless version < minimum

        "Rails #{version} is not supported; Rails #{minimum} or newer is required"
      rescue ArgumentError
        'Rails is detected but its version cannot be determined'
      end

      def detected_versions(snapshot, loaded_specs)
        versions = snapshot ? RAILS_GEMS.flat_map { |name| snapshot.versions(name) } : []
        RAILS_GEMS.each do |name|
          loaded = loaded_specs[name]
          versions << loaded.version.to_s if loaded
        end
        versions.uniq
      end
    end
  end
end
