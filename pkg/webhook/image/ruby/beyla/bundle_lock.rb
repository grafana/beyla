# frozen_string_literal: true

require 'bundler'
require_relative 'log'

# bundle_lock.rb safely reads the application’s Gemfile.lock without evaluating its Gemfile
module Beyla
  module OpenTelemetry
    class BundleSnapshot
      attr_reader :direct_dependencies

      def initialize(parser)
        @direct_dependencies = parser.dependencies.keys
        @versions = parser.specs.group_by(&:name).transform_values do |specs|
          specs.map { |spec| spec.version.to_s }.uniq
        end
      end

      def detected?(name)
        @versions.key?(name)
      end

      def versions(name)
        @versions.fetch(name, [])
      end
    end

    module BundleLock
      module_function

      def load
        path = Bundler.default_lockfile
        unless path.file?
          Log.debug("bundle lockfile not found at #{path}")
          return
        end

        parser = Bundler::LockfileParser.new(Bundler.read_file(path))
        BundleSnapshot.new(parser)
      rescue StandardError => e
        Log.debug("bundle lockfile unavailable: #{e.message}")
        nil
      end
    end
  end
end
