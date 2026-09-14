# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    # The Base class holds all metadata and configuration for an
    # instrumentation. All instrumentation packages should
    # include a subclass of +Instrumentation::Base+ that will register
    # it with +OpenTelemetry.instrumentation_registry+ and make it available for
    # discovery and installation by an SDK.
    #
    # A typical subclass of Base will provide an install block, a present
    # block, and possibly a compatible block. Below is an
    # example:
    #
    # module OpenTelemetry
    #   module Instrumentation
    #     module Sinatra
    #       class Instrumentation < OpenTelemetry::Instrumentation::Base
    #         install do |config|
    #           # install instrumentation, either by library hook or applying
    #           # a monkey patch
    #         end
    #
    #         # determine if the target library is present
    #         present do
    #           defined?(::Sinatra)
    #         end
    #
    #         # if the target library is present, is it compatible?
    #         compatible do
    #           Gem::Version.new(Sinatra::VERSION)) > MIN_VERSION
    #         end
    #       end
    #     end
    #   end
    # end
    #
    # The instrumentation name and version will be inferred from the namespace of the
    # class. In this example, they'd be 'OpenTelemetry::Instrumentation::Sinatra' and
    # OpenTelemetry::Instrumentation::Sinatra::VERSION, but can be explicitly set using
    # the +instrumentation_name+ and +instrumentation_version+ methods if necessary.
    #
    # All subclasses of OpenTelemetry::Instrumentation::Base are automatically
    # registered with OpenTelemetry.instrumentation_registry which is used by
    # SDKs for instrumentation discovery and installation.
    #
    # Instrumentation libraries can use the instrumentation subclass to easily gain
    # a reference to its named tracer. For example:
    #
    # OpenTelemetry::Instrumentation::Sinatra.instance.tracer
    #
    # The instrumentation class establishes a convention for disabling an instrumentation
    # by environment variable and local configuration. An instrumentation disabled
    # by environment variable will take precedence over local config. The
    # convention for environment variable name is the library name, upcased with
    # '::' replaced by underscores, OPENTELEMETRY shortened to OTEL_{LANG}, and '_ENABLED' appended.
    # For example: OTEL_RUBY_INSTRUMENTATION_SINATRA_ENABLED = false.
    class Base
      class << self
        NAME_REGEX = /^(?:(?<namespace>[a-zA-Z0-9_:]+):{2})?(?<classname>[a-zA-Z0-9_]+)$/
        VALIDATORS = {
          array: ->(v) { v.is_a?(Array) },
          boolean: ->(v) { v == true || v == false }, # rubocop:disable Style/MultipleComparison
          callable: ->(v) { v.respond_to?(:call) },
          integer: ->(v) { v.is_a?(Integer) },
          string: ->(v) { v.is_a?(String) }
        }.freeze

        private_constant :NAME_REGEX, :VALIDATORS

        private :new

        def inherited(subclass) # rubocop:disable Lint/MissingSuper
          OpenTelemetry::Instrumentation.registry.register(subclass)
        end

        # Optionally set the name of this instrumentation. If not
        # explicitly set, the name will default to the namespace of the class,
        # or the class name if it does not have a namespace. If there is not
        # a namespace, or a class name, it will default to 'unknown'.
        #
        # @param [String] instrumentation_name The full name of the instrumentation package
        def instrumentation_name(instrumentation_name = nil)
          if instrumentation_name
            @instrumentation_name = instrumentation_name
          else
            @instrumentation_name ||= infer_name || 'unknown'
          end
        end

        # Optionally set the version of this instrumentation. If not explicitly set,
        # the version will default to the VERSION constant under namespace of
        # the class, or the VERSION constant under the class name if it does not
        # have a namespace. If a VERSION constant cannot be found, it defaults
        # to '0.0.0'.
        #
        # @param [String] instrumentation_version The version of the instrumentation package
        def instrumentation_version(instrumentation_version = nil)
          if instrumentation_version
            @instrumentation_version = instrumentation_version
          else
            @instrumentation_version ||= infer_version || '0.0.0'
          end
        end

        # The install block for this instrumentation. This will be where you install
        # instrumentation, either by framework hook or applying a monkey patch.
        #
        # @param [Callable] blk The install block for this instrumentation
        # @yieldparam [Hash] config The instrumentation config will be yielded to the
        #   install block
        def install(&blk)
          @install_blk = blk
        end

        # The present block for this instrumentation. This block is used to detect if
        # target library is present on the system. Typically this will involve
        # checking to see if the target gem spec was loaded or if expected
        # constants from the target library are present.
        #
        # @param [Callable] blk The present block for this instrumentation
        def present(&blk)
          @present_blk = blk
        end

        # The compatible block for this instrumentation. This check will be run if the
        # target library is present to determine if it's compatible. It's not
        # required, but a common use case will be to check to target library
        # version for compatibility.
        #
        # @param [Callable] blk The compatibility block for this instrumentation
        def compatible(&blk)
          @compatible_blk = blk
        end

        # The option method is used to define default configuration options
        # for the instrumentation library. It requires a name, default value,
        # and a validation callable to be provided.
        # @param [String] name The name of the configuration option
        # @param default The default value to be used, or to used if validation fails
        # @param [Callable, Symbol] validate Accepts a callable or a symbol that matches
        # a key in the VALIDATORS hash.  The supported keys are, :array, :boolean,
        # :callable, :integer, :string.
        def option(name, default:, validate:)
          validator = VALIDATORS[validate] || validate
          raise ArgumentError, "validate must be #{VALIDATORS.keys.join(', ')}, or a callable" unless validator.respond_to?(:call) || validator.respond_to?(:include?)

          @options ||= []

          validation_type = if VALIDATORS[validate]
                              validate
                            elsif validate.respond_to?(:include?)
                              :enum
                            else
                              :callable
                            end

          @options << { name: name, default: default, validator: validator, validation_type: validation_type }
        end

        def instance
          @instance ||= new(instrumentation_name, instrumentation_version, install_blk,
                            present_blk, compatible_blk, options)
        end

        private

        attr_reader :install_blk, :present_blk, :compatible_blk, :options

        def infer_name
          @inferred_name ||= if (md = name.match(NAME_REGEX)) # rubocop:disable Naming/MemoizedInstanceVariableName
                               md['namespace'] || md['classname']
                             end
        end

        def infer_version
          return unless (inferred_name = infer_name)

          mod = inferred_name.split('::').map(&:to_sym).inject(Object) do |object, const|
            object.const_get(const)
          end
          mod.const_get(:VERSION)
        rescue NameError
          nil
        end
      end

      attr_reader :name, :version, :config, :installed, :tracer

      alias installed? installed

      # rubocop:disable Metrics/ParameterLists
      def initialize(name, version, install_blk, present_blk,
                     compatible_blk, options)
        @name = name
        @version = version
        @install_blk = install_blk
        @present_blk = present_blk
        @compatible_blk = compatible_blk
        @options = options
        # Empty hash that falls back to option defaults for missing keys
        defaults = (@options || []).to_h { |opt| [opt[:name], opt[:default]] }
        @config = Hash.new { |_, k| defaults[k] }
        @installed = false
        @tracer = OpenTelemetry::Trace::Tracer.new
      end
      # rubocop:enable Metrics/ParameterLists

      # Install instrumentation with the given config. The present? and compatible?
      # will be run first, and install will return false if either fail. Will
      # return true if install was completed successfully.
      #
      # @param [Hash] config The config for this instrumentation
      def install(config = {})
        return true if installed?

        @config = config_options(config)
        return false unless installable?(config)

        instance_exec(@config, &@install_blk)
        @tracer = OpenTelemetry.tracer_provider.tracer(name, version)
        @installed = true
      end

      # Whether or not this instrumentation is installable in the current process. Will
      # be true when the instrumentation defines an install block, is not disabled
      # by environment or config, and the target library present and compatible.
      #
      # @param [Hash] config The config for this instrumentation
      def installable?(config = {})
        @install_blk && enabled?(config) && present? && compatible?
      end

      # Calls the present block of the Instrumentation subclasses, if no block is provided
      # it's assumed the instrumentation is not present
      def present?
        return false unless @present_blk

        instance_exec(&@present_blk)
      end

      # Calls the compatible block of the Instrumentation subclasses, if no block is provided
      # it's assumed to be compatible
      def compatible?
        return true unless @compatible_blk

        instance_exec(&@compatible_blk)
      end

      # Whether this instrumentation is enabled. It first checks to see if it's enabled
      # by an environment variable and will proceed to check if it's enabled
      # by local config, if given.
      #
      # @param [optional Hash] config The local config
      def enabled?(config = nil)
        return false unless enabled_by_env_var?
        return config[:enabled] if config&.key?(:enabled)

        true
      end

      private

      # The config_options method is responsible for validating that the user supplied
      # config hash is valid.
      # Unknown configuration keys are not included in the final config hash.
      # Invalid configuration values are logged, and replaced by the default.
      #
      # @param [Hash] user_config The user supplied configuration hash
      def config_options(user_config)
        @options ||= {}
        user_config ||= {}
        config_overrides = config_overrides_from_env
        validated_config = @options.each_with_object({}) do |option, h|
          option_name = option[:name]
          config_value = user_config[option_name]
          config_override = coerce_env_var(config_overrides[option_name], option[:validation_type]) if config_overrides[option_name]

          # rubocop:disable Lint/DuplicateBranch
          value = if config_value.nil? && config_override.nil?
                    option[:default]
                  elsif option[:validator].respond_to?(:include?) && option[:validator].include?(config_override)
                    config_override
                  elsif option[:validator].respond_to?(:include?) && option[:validator].include?(config_value)
                    config_value
                  elsif option[:validator].respond_to?(:call) && option[:validator].call(config_override)
                    config_override
                  elsif option[:validator].respond_to?(:call) && option[:validator].call(config_value)
                    config_value
                  else
                    OpenTelemetry.logger.warn(
                      "Instrumentation #{name} configuration option #{option_name} value=#{config_value} " \
                      "failed validation, falling back to default value=#{option[:default]}"
                    )
                    option[:default]
                  end
          # rubocop:enable Lint/DuplicateBranch

          h[option_name] = value
        rescue StandardError => e
          OpenTelemetry.handle_error(exception: e, message: "Instrumentation #{name} unexpected configuration error")
          h[option_name] = option[:default]
        end

        dropped_config_keys = user_config.keys - validated_config.keys - [:enabled]
        OpenTelemetry.logger.warn("Instrumentation #{name} ignored the following unknown configuration options #{dropped_config_keys}") unless dropped_config_keys.empty?

        validated_config
      end

      # Checks to see if this instrumentation is enabled by env var. By convention, the
      # environment variable will be the instrumentation name upper cased, with '::'
      # replaced by underscores, OPENTELEMETRY shortened to OTEL_{LANG} and _ENABLED appended.
      # For example, the, environment variable name for OpenTelemetry::Instrumentation::Sinatra
      # will be OTEL_RUBY_INSTRUMENTATION_SINATRA_ENABLED. A value of 'false' will disable
      # the instrumentation, all other values will enable it.
      def enabled_by_env_var?
        var_name = name.dup.tap do |n|
          n.upcase!
          n.gsub!('::', '_')
          n.gsub!('OPENTELEMETRY_', 'OTEL_RUBY_')
          n << '_ENABLED'
        end
        ENV[var_name] != 'false'
      end

      # Checks to see if the user has passed any environment variables that set options
      # for instrumentation. By convention, the environment variable will be the name
      # of the instrumentation, upper-cased, with '::' replaced by underscores,
      # OPENTELEMETRY shortened to OTEL_{LANG}, and _CONFIG_OPTS appended.
      # For example, the environment variable name for OpenTelemetry::Instrumentation::Faraday
      # will be OTEL_RUBY_INSTRUMENTATION_FARADAY_CONFIG_OPTS. A value of 'peer_service=new_service;'
      # will override the options set from ::OpenTelemetry::SDK.configure do |c| ... end for Faraday.
      #
      # For an array option, simply separate the values with commas (e.g., option=a,b,c,d).
      # For a boolean option, set the value to true or false (e.g., option=true).
      # For integer, string, enum, set the value as a string (e.g., option=string).
      # Callable options are not allowed to be set through environment variables.
      def config_overrides_from_env
        var_name = name.dup.tap do |n|
          n.upcase!
          n.gsub!('::', '_')
          n.gsub!('OPENTELEMETRY_', 'OTEL_RUBY_')
          n << '_CONFIG_OPTS'
        end

        environment_config_overrides = {}
        env_config_options = ENV[var_name]&.split(';')

        return environment_config_overrides if env_config_options.nil?

        env_config_options.each_with_object(environment_config_overrides) do |env_config_option, eco|
          parts = env_config_option.split('=')
          option_name = parts[0].to_sym
          eco[option_name] = parts[1]
        end

        environment_config_overrides
      end

      def coerce_env_var(env_var, validation_type)
        case validation_type
        when :array
          env_var.split(',').map(&:strip)
        when :boolean
          env_var.to_s.strip.casecmp('true').zero?
        when :integer
          env_var.to_i
        when :string
          env_var.to_s.strip
        when :enum
          env_var.to_s.strip.to_sym
        when :callable
          OpenTelemetry.logger.warn(
            "Instrumentation #{name} options that accept a callable are not " \
            "configurable using environment variables. Ignoring raw value: #{env_var}"
          )
          nil
        end
      end
    end
  end
end
