# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsSdk
      # The `OpenTelemetry::Instrumentation::AwsSdk::Instrumentation` class contains
      # logic to detect and install the AwsSdk instrumentation.
      #
      # ## Configuration keys and options
      #
      # ### `:inject_messaging_context`
      #
      # Allows adding of context key/value to Message Attributes for SQS/SNS messages.
      #
      # - `false` **(default)** - Context key/value will not be added.
      # - `true` - Context key/value will be added.
      #
      # ### `:enable_internal_instrumentation`
      # Enables tracing of spans of `internal` span kind.
      #
      # - `false` **(default)** - Internal spans are not traced
      # - `true` - Internal spans are traced.
      #
      # ### `:suppress_internal_instrumentation` (deprecated)
      # This configuration has been deprecated in favor of `:enable_internal_instrumentation`
      #
      # @example An explicit default configuration
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use 'OpenTelemetry::Instrumentation::AwsSdk', {
      #       inject_messaging_context: false,
      #       enable_internal_instrumentation: false
      #     }
      #   end
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('2.0.0')

        install do |config|
          resolve_config(config)
          require_dependencies
          patch_telemetry_plugin if telemetry_plugin?
          add_plugins(Seahorse::Client::Base, *loaded_service_clients)
        end

        present do
          !defined?(::Seahorse::Client::Base).nil?
        end

        compatible do
          !gem_version.nil? && gem_version >= MINIMUM_VERSION
        end

        option :inject_messaging_context, default: false, validate: :boolean
        option :suppress_internal_instrumentation, default: false, validate: :boolean
        option :enable_internal_instrumentation, default: false, validate: :boolean

        def gem_version
          if Gem.loaded_specs['aws-sdk']
            Gem.loaded_specs['aws-sdk'].version
          elsif Gem.loaded_specs['aws-sdk-core']
            Gem.loaded_specs['aws-sdk-core'].version
          elsif defined?(::Aws::CORE_GEM_VERSION)
            Gem::Version.new(::Aws::CORE_GEM_VERSION)
          end
        end

        private

        def resolve_config(config)
          return unless config[:suppress_internal_instrumentation]

          OpenTelemetry.logger.warn(
            'Instrumentation AwsSdk configuration option suppress_internal_instrumentation has been deprecated,' \
            'use enable_internal_instrumentation option instead'
          )
        end

        def require_dependencies
          require_relative 'handler'
          require_relative 'handler_helper'
          require_relative 'message_attributes'
          require_relative 'messaging_helper'
          require_relative 'patches/telemetry'
        end

        def add_plugins(*targets)
          targets.each do |klass|
            next if supports_telemetry_plugin?(klass)

            klass.add_plugin(AwsSdk::Plugin)
          end
        end

        def supports_telemetry_plugin?(klass)
          telemetry_plugin? &&
            klass.plugins.include?(Aws::Plugins::Telemetry)
        end

        def telemetry_plugin?
          ::Aws::Plugins.const_defined?(:Telemetry)
        end

        # Patches AWS SDK V3's telemetry plugin for integration
        # This patch supports configuration set by this gem and
        # additional span attributes that were not provided by the plugin
        def patch_telemetry_plugin
          ::Aws::Plugins::Telemetry::Handler.prepend(Patches::Handler)
        end

        def loaded_service_clients
          ::Aws.constants.each_with_object([]) do |c, constants|
            m = ::Aws.const_get(c)
            next unless loaded_service?(c, m)

            begin
              constants << m.const_get(:Client)
            rescue StandardError => e
              OpenTelemetry.logger.warn("Constant could not be loaded: #{e}")
            end
          end
        end

        # This check does the following:
        # 1 - Checks if the service client is autoload or not
        # 2 - Validates whether it is a service client
        # note that Seahorse::Client::Base is a superclass for V3 clients
        # but for V2, it is Aws::Client
        # rubocop:disable Style/MultipleComparison
        def loaded_service?(constant, service_module)
          !::Aws.autoload?(constant) &&
            service_module.is_a?(Module) &&
            service_module.const_defined?(:Client) &&
            (service_module.const_get(:Client).superclass == Seahorse::Client::Base ||
              service_module.const_get(:Client).superclass == Aws::Client)
        end
        # rubocop:enable Style/MultipleComparison
      end
    end
  end
end
