# frozen_string_literal: true

require 'rubygems'
require_relative 'dependency_requirements'
require_relative 'required_features'

module Beyla
  module OpenTelemetry
    module OpenTelemetryGuard
      API_GEM = 'opentelemetry-api'

      module_function

      def rejection(snapshot, rubyopt, entrypoint, loaded_features = $LOADED_FEATURES)
        return 'OpenTelemetry is already loaded' if loaded?(loaded_features, entrypoint)
        reason = bundle_rejection(snapshot)
        return reason if reason
        return 'RUBYOPT already preloads OpenTelemetry' if preloaded?(rubyopt, entrypoint)
      end

      def loaded?(loaded_features, entrypoint)
        loaded_features.any? do |feature|
          feature.downcase.include?('opentelemetry') && !same_feature?(feature, entrypoint)
        end
      end

      def bundle_rejection(snapshot)
        return unless snapshot
        return 'the application bundle declares OpenTelemetry gems' if disallowed_gems(snapshot).any?
        return unless snapshot.detected?(API_GEM)

        version = api_version(snapshot)
        return 'the application opentelemetry-api version cannot be determined' unless version
        return if compatible_api?(version)

        "the application opentelemetry-api version #{version} is incompatible"
      end

      def disallowed_gems(snapshot)
        snapshot.direct_dependencies.select do |name|
          name != API_GEM && (name == 'opentelemetry' || name.start_with?('opentelemetry-'))
        end
      end

      def api_version(snapshot)
        versions = snapshot.versions(API_GEM)
        Gem::Version.new(versions.first) if versions.one?
      rescue ArgumentError
        nil
      end

      def compatible_api?(version)
        Compatibility::OPENTELEMETRY_API_REQUIREMENTS.all? do |requirement|
          Gem::Requirement.new(requirement).satisfied_by?(version)
        end
      end

      def preloaded?(rubyopt, entrypoint)
        RequiredFeatures.parse(rubyopt).any? do |feature|
          feature.downcase.include?('opentelemetry') && !same_feature?(feature, entrypoint)
        end
      end

      def same_feature?(feature, entrypoint)
        normalize(feature) == normalize(entrypoint)
      end

      def normalize(path)
        File.expand_path(path.sub(/\.rb\z/, ''))
      end
    end
  end
end
