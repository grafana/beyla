# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module GraphQL
      # The Instrumentation class contains logic to detect and install the GraphQL instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        compatible do
          if config[:legacy_tracing]
            supports_legacy_tracer?
          else
            supports_new_tracer?
          end
        end

        install do |config|
          if config[:legacy_tracing]
            require_relative 'tracers/graphql_tracer'
            install_tracer(config)
          else
            require_relative 'tracers/graphql_trace'
            install_new_tracer(config)
          end

          patch
        end

        present do
          defined?(::GraphQL)
        end

        def supports_legacy_tracer?
          Gem::Requirement.new('!= 2.0.18').satisfied_by?(gem_version)
        end

        def supports_new_tracer?
          Gem::Requirement.new('>= 2.0.19').satisfied_by?(gem_version)
        end

        def dataloader_has_spawn_fiber?
          Gem::Requirement.new('>= 2.1.8').satisfied_by?(gem_version)
        end

        ## Supported configuration keys for the install config hash:
        #
        # The enable_platform_field key expects a boolean value,
        # and enables the tracing of "execute_field" and "execute_field_lazy".
        #
        # The enable_platform_authorized key expects a boolean value,
        # and enables the tracing of "authorized" and "authorized_lazy".
        #
        # The enable_platform_resolve_type key expects a boolean value,
        # and enables the tracing of "resolve_type" and "resolve_type_lazy".
        #
        # The legacy_platform_span_names key expects a boolean value,
        # and controls if platform tracing (field/authorized/resolve_type)
        # should use the legacy span names (e.g. "MyType.myField") or the
        # new normalized span names (e.g. "graphql.execute_field").
        #
        # The schemas key expects an array of Schemas, and is used to specify
        # which schemas are to be instrumented. If this value is not supplied
        # the default behaviour is to instrument all schemas.
        option :schemas,                      default: [],    validate: :array
        option :enable_platform_field,        default: false, validate: :boolean
        option :enable_platform_authorized,   default: false, validate: :boolean
        option :enable_platform_resolve_type, default: false, validate: :boolean
        option :legacy_platform_span_names,   default: false, validate: :boolean
        option :legacy_tracing,               default: false, validate: :boolean

        private

        def gem_version
          Gem::Version.new(::GraphQL::VERSION)
        end

        def install_tracer(config = {})
          if config[:schemas].empty?
            ::GraphQL::Schema.tracer(Tracers::GraphQLTracer.new)
          else
            config[:schemas].each do |schema|
              schema.use(Tracers::GraphQLTracer)
            rescue StandardError => e
              OpenTelemetry.logger.error("Unable to patch schema #{schema}: #{e.message}")
            end
          end
        end

        def install_new_tracer(config = {})
          if config[:schemas].empty?
            ::GraphQL::Schema.trace_with(Tracers::GraphQLTrace)
          else
            config[:schemas].each do |schema|
              schema.trace_with(Tracers::GraphQLTrace)
            rescue StandardError => e
              OpenTelemetry.logger.error("Unable to patch schema #{schema}: #{e.message}")
            end
          end
        end

        def patch
          return unless dataloader_has_spawn_fiber?

          require_relative 'patches/dataloader'
          ::GraphQL::Dataloader.prepend(Patches::Dataloader)
        end
      end
    end
  end
end
