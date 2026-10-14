# frozen_string_literal: true

require_relative 'log'
require_relative 'rails_service_name'

module Beyla
  module OpenTelemetry
    module RailsResourceDetector
      SERVICE_NAME = 'service.name'
      UNKNOWN_SERVICE = 'unknown_service'
      SOURCES = {
        application_class: 'Rails application class',
        project_directory: 'Rails project directory'
      }.freeze

      module InitializerPatch
        def _otel_detect_resource_from_env
          RailsResourceDetector.merge(super)
        end
      end

      module_function

      def install(initializer = upstream_initializer)
        singleton = initializer.singleton_class
        singleton.prepend(InitializerPatch) unless singleton.ancestors.include?(InitializerPatch)
      rescue StandardError => e
        Log.debug("Rails resource detector installation failed: #{e.message}")
      end

      def merge(upstream, resource_class: sdk_resource)
        existing = resource_class.default.merge(upstream)
        name = service_name(existing)
        return use_existing(upstream, name) unless missing_name?(name)

        merge_detected_name(upstream, name, resource_class)
      rescue StandardError => e
        Log.debug("Rails resource detection failed: #{e.message}")
        upstream
      end

      def service_name(resource)
        resource.attribute_enumerator.to_h[SERVICE_NAME]
      end

      def missing_name?(name)
        name.nil? || name.empty? || name == UNKNOWN_SERVICE
      end

      def use_existing(upstream, name)
        Log.info("using service.name=#{name.inspect} from OpenTelemetry resource detectors")
        upstream
      end

      def merge_detected_name(upstream, existing_name, resource_class)
        Log.info('service.name was not found by OpenTelemetry resource detectors; looking for a Rails service name')
        detection = RailsServiceName.detect
        return no_detection(upstream, existing_name) unless detection

        Log.info("using service.name=#{detection.name.inspect} detected from #{SOURCES.fetch(detection.source)}")
        upstream.merge(resource_class.create(SERVICE_NAME => detection.name))
      end

      def no_detection(upstream, existing_name)
        Log.info("Rails service name detection found no name; keeping service.name=#{existing_name.inspect}")
        upstream
      end

      def upstream_initializer
        ::OTelBundlerPatch::OTelInitializer
      end

      def sdk_resource
        ::OpenTelemetry::SDK::Resources::Resource
      end

      private_class_method :service_name, :missing_name?, :use_existing, :merge_detected_name, :no_detection,
                           :upstream_initializer, :sdk_resource
    end
  end
end
