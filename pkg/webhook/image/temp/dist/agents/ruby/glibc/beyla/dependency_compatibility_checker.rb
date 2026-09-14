# frozen_string_literal: true

require 'rubygems'
require_relative 'compatibility'

module Beyla
  module OpenTelemetry
    class DependencyCheck
      attr_reader :exclusions, :load_paths, :rejection

      def initialize(exclusions, load_paths, rejection = nil)
        @exclusions = exclusions
        @load_paths = load_paths
        @rejection = rejection
      end
    end

    class DependencyCompatibilityChecker
      def initialize(snapshot, bundle_root, env = ENV, loaded_specs = Gem.loaded_specs)
        @snapshot = snapshot
        @bundle_root = File.expand_path(bundle_root)
        @loaded_specs = loaded_specs
        @user_exclusions = parse_exclusions(env['DISALLOWED_LIB_PATH'])
      end

      def check_dependencies
        exclusions = @user_exclusions.dup
        load_paths = []

        Compatibility::DEPENDENCY_REQUIREMENTS.each_key do |name|
          next unless detected?(name)

          result = resolve(name)
          return DependencyCheck.new(exclusions, load_paths, result[:rejection]) if result[:rejection]

          exclusions << name
          load_paths.concat(result[:load_paths])
        end

        DependencyCheck.new(exclusions.uniq, load_paths.uniq)
      end

      private

      def detected?(name)
        loaded_spec(name) || (@snapshot && @snapshot.detected?(name)) || @user_exclusions.include?(name)
      end

      def resolve(name)
        versions = detected_versions(name)
        return rejected(name, 'version cannot be determined') unless versions.one?

        version = parse_version(versions.first)
        return rejected(name, 'version cannot be determined') unless version
        return rejected(name, "version #{version} is incompatible") unless compatible?(name, version)

        loaded = loaded_spec(name)
        if loaded && injected?(loaded)
          return rejected(name, 'was loaded from the injection bundle before compatibility checks')
        end
        return resolved([]) if loaded && loaded.version == version

        spec = application_specs(name).find { |candidate| candidate.version == version }
        return rejected(name, "version #{version} is not available to the application") unless spec

        resolved(spec.full_require_paths)
      end

      def detected_versions(name)
        versions = @snapshot ? @snapshot.versions(name) : []
        loaded = loaded_spec(name)
        versions += [loaded.version.to_s] if loaded
        if versions.empty? && @user_exclusions.include?(name)
          versions = application_specs(name).map { |spec| spec.version.to_s }
        end
        versions.uniq
      end

      def loaded_spec(name)
        @loaded_specs[name]
      end

      def application_specs(name)
        Gem::Specification.find_all_by_name(name).reject { |spec| injected?(spec) }
      rescue Gem::LoadError
        []
      end

      def injected?(spec)
        File.expand_path(spec.full_gem_path).start_with?("#{@bundle_root}#{File::SEPARATOR}")
      end

      def compatible?(name, version)
        Compatibility::DEPENDENCY_REQUIREMENTS.fetch(name).all? do |requirement|
          Gem::Requirement.new(requirement).satisfied_by?(version)
        end
      end

      def parse_version(value)
        Gem::Version.new(value)
      rescue ArgumentError
        nil
      end

      def parse_exclusions(value)
        value.to_s.split(',').map(&:strip).reject(&:empty?)
      end

      def rejected(name, detail)
        { rejection: "#{name} #{detail}" }
      end

      def resolved(load_paths)
        { load_paths: load_paths }
      end
    end
  end
end
