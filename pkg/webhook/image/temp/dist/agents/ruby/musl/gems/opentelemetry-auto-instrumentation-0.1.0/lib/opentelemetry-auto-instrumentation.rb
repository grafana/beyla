# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative 'opentelemetry/auto_instrumentation/version'

# OTelBundlerPatch
module OTelBundlerPatch
  # Nested module to handle OpenTelemetry initialization logic
  module OTelInitializer
    @_otel_mutex = Mutex.new
    @_otel_initialized = false

    # Returns all instrumentation classes registered in the OpenTelemetry instrumentation registry.
    def self._otel_registry_instrumentation_classes
      registry = ::OpenTelemetry::Instrumentation.registry

      # The registry only exposes lookup/install methods publicly, so enumerate
      # the internal collection to derive supported instrumentation names.
      registry.instance_variable_get(:@instrumentation) || []
    rescue StandardError
      []
    end

    # Converts a CamelCase or hyphenated string to snake_case.
    def self._otel_snake_case(value)
      value
        .gsub(/([A-Z]+)([A-Z][a-z])/, '\\1_\\2')
        .gsub(/([a-z\\d])([A-Z])/, '\\1_\\2')
        .tr('-', '_')
        .downcase
    end

    # Returns all snake_case alias strings for a given fully-qualified instrumentation name.
    def self._otel_registry_aliases_for(instrumentation_name)
      suffix = instrumentation_name.delete_prefix('OpenTelemetry::Instrumentation::')
      segment_variants = suffix.split('::').map do |segment|
        snake = _otel_snake_case(segment)
        compact = segment.downcase
        [snake, compact].uniq
      end

      segment_variants.reduce(['']) do |aliases, variants|
        aliases.flat_map do |alias_prefix|
          variants.map { |variant| alias_prefix.empty? ? variant : "#{alias_prefix}_#{variant}" }
        end
      end
    end

    # Builds and caches a hash mapping alias names to canonical instrumentation names.
    def self._otel_registry_lookup
      @_otel_registry_lookup ||= _otel_registry_instrumentation_classes.each_with_object({}) do |instrumentation_class, lookup|
        instrumentation_name = instrumentation_class.instance.name
        _otel_registry_aliases_for(instrumentation_name).each do |alias_name|
          lookup[alias_name] ||= instrumentation_name
        end
      rescue StandardError
        next
      end
    end

    # Detects and merges resource attributes from detectors listed in OTEL_RUBY_RESOURCE_DETECTORS.
    def self._otel_detect_resource_from_env
      resource_map = {
        'container' => (defined?(::OpenTelemetry::Resource::Detector::Container) ? ::OpenTelemetry::Resource::Detector::Container : nil),
        'azure' => (defined?(::OpenTelemetry::Resource::Detector::Azure) ? ::OpenTelemetry::Resource::Detector::Azure : nil),
        'aws' => (defined?(::OpenTelemetry::Resource::Detector::AWS) ? ::OpenTelemetry::Resource::Detector::AWS : nil)
      }

      ENV['OTEL_RUBY_RESOURCE_DETECTORS'].to_s.split(',').map(&:strip).reject(&:empty?).reduce(::OpenTelemetry::SDK::Resources::Resource.create({})) do |resource, detector|
        detector_class = resource_map[detector]
        detector_class ? resource.merge(detector_class.detect) : resource
      end
    end

    # Creates a Resource containing distro name and version attributes.
    def self._otel_distro_resource
      ::OpenTelemetry::SDK::Resources::Resource.create(
        {
          'telemetry.distro.name' => 'opentelemetry-ruby-instrumentation',
          'telemetry.distro.version' => ::OpenTelemetry::AutoInstrumentation::VERSION
        }
      )
    end

    # Returns a list of canonical instrumentation names enabled via OTEL_RUBY_ENABLED_INSTRUMENTATIONS.
    def self._otel_determine_enabled_instrumentation
      env = ENV['OTEL_RUBY_ENABLED_INSTRUMENTATIONS'].to_s

      return [] if env.strip.empty?

      instrumentation_lookup = _otel_registry_lookup

      env.split(',').filter_map do |instrumentation|
        normalized = instrumentation.strip.downcase
        value = instrumentation_lookup[normalized]
        warn "[OpenTelemetry] WARNING: Unknown instrumentation '#{instrumentation.strip}'" if value.nil? && ENV['OTEL_RUBY_AUTO_INSTRUMENTATION_DEBUG'] == 'true'
        value
      end
    end

    # Warns if any opentelemetry- gems are found in the Gemfile, as they may conflict with auto-instrumentation.
    def self._otel_check_for_bundled_otel_gems
      bundled_otel_gems = Bundler.definition.dependencies.select do |dep|
        dep.name.start_with?('opentelemetry-')
      end

      return if bundled_otel_gems.empty?

      gem_names = bundled_otel_gems.map(&:name).sort.join(', ')
      warn '[OpenTelemetry] WARNING: Detected OpenTelemetry gems in your Gemfile: ' \
           "#{gem_names}. When using opentelemetry-auto-instrumentation, OpenTelemetry gems are loaded " \
           'from the opentelemetry-auto-instrumentation gem path, NOT from your bundle. The gem versions ' \
           'in your Gemfile/Gemfile.lock are not used and may cause version conflicts or ' \
           'unexpected behavior. Please remove these gems from your Gemfile when using ' \
           'opentelemetry-auto-instrumentation.'
    rescue StandardError => e
      warn "[OpenTelemetry] WARNING: Unable to check Gemfile for OpenTelemetry gems: #{e.message}" if ENV['OTEL_RUBY_AUTO_INSTRUMENTATION_DEBUG'] == 'true'
    end

    # Initializes the OpenTelemetry SDK exactly once using a mutex-protected check.
    def self._otel_require_otel
      @_otel_mutex.synchronize do
        return if @_otel_initialized

        @_otel_initialized = true

        begin
          _otel_check_for_bundled_otel_gems

          required_instrumentation = _otel_determine_enabled_instrumentation

          resource = _otel_detect_resource_from_env
          resource = resource.merge(_otel_distro_resource)

          OpenTelemetry::SDK.configure do |c|
            c.resource = resource
            if required_instrumentation.empty?
              c.use_all
            else
              required_instrumentation.each do |instrumentation|
                c.use instrumentation
              end
            end
          end

          OpenTelemetry.logger.info { 'Auto-instrumentation initialized' }
        rescue StandardError => e
          @_otel_initialized = false
          warn "Auto-instrumentation failed to initialize. Error: #{e.message}"
        end
      end
    end
  end

  # Overrides Kernel#require to trigger OpenTelemetry initialization after each require call.
  def require(...)
    super
    OTelInitializer._otel_require_otel
  end
end

require 'bundler'

ADDITIONAL_LIB_GEM_ALLOWLIST = %w[
  googleapis-common-protos-types
  google-protobuf
].freeze

parse_env_list = lambda do |key|
  ENV[key].to_s.split(',').map(&:strip).reject(&:empty?)
end

# /otel-auto-instrumentation-ruby is default path for otel operator (ruby.go)
# If requires different gem path to load gem, set env OTEL_RUBY_ADDITIONAL_GEM_PATH
gem_path = ENV['OTEL_RUBY_ADDITIONAL_GEM_PATH'] || '/otel-auto-instrumentation-ruby'
gem_path = Gem.dir unless Dir.exist?(gem_path)

gem_entries = Dir.glob("#{gem_path}/gems/*")

# googleapis-common-protos-types and google-protobuf are dependencies for otlp exporters
# google-cloud-env are dependencies for gcp resource detectors
otel_lib_path = gem_entries.select do |file_path|
  File.basename(file_path).start_with?('opentelemetry-')
end

disallowed_lib_paths = parse_env_list.call('DISALLOWED_LIB_PATH')
allowed_additional_lib_gems = ADDITIONAL_LIB_GEM_ALLOWLIST - disallowed_lib_paths

additional_lib_path = gem_entries.select do |file_path|
  gem_dir_name = File.basename(file_path)
  allowed_additional_lib_gems.any? { |gem_name| gem_dir_name.start_with?("#{gem_name}-") }
end

# unshift file_path add opentelemetry component at the top of $LOAD_PATH
otel_lib_path.each { |file_path| $LOAD_PATH.unshift("#{file_path}/lib") }
additional_lib_path.each { |file_path| $LOAD_PATH.unshift("#{file_path}/lib") }

warn "Loading the gem path from #{gem_path}\n$LOAD_PATH after unshift: #{$LOAD_PATH.join(',')}" if ENV['OTEL_RUBY_AUTO_INSTRUMENTATION_DEBUG'] == 'true'

# These are required for the prepend OTelBundlerPatch to fetch OpenTelemetry::SDK.configure
require 'opentelemetry-sdk'
require 'opentelemetry-metrics-sdk'
require 'opentelemetry-logs-sdk'
require 'opentelemetry-exporter-otlp'
require 'opentelemetry-exporter-otlp-metrics'
require 'opentelemetry-exporter-otlp-logs'
require 'opentelemetry-instrumentation-all'

resource_detectors = parse_env_list.call('OTEL_RUBY_RESOURCE_DETECTORS')
require 'opentelemetry-resource-detector-container' if resource_detectors.include?('container')
require 'opentelemetry-resource-detector-azure' if resource_detectors.include?('azure')
require 'opentelemetry-resource-detector-aws' if resource_detectors.include?('aws')

Bundler::Runtime.prepend(OTelBundlerPatch)

Bundler.require if ENV['OTEL_RUBY_REQUIRE_BUNDLER'] == 'true'
