# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module GraphQL
      module Tracers
        # GraphQLTracer contains the OpenTelemetry tracer implementation compatible with
        # the GraphQL tracer API
        class GraphQLTracer < ::GraphQL::Tracing::PlatformTracing
          DEFAULT_HASH = {}.freeze

          self.platform_keys = {
            'lex' => 'graphql.lex',
            'parse' => 'graphql.parse',
            'validate' => 'graphql.validate',
            'analyze_query' => 'graphql.analyze_query',
            'analyze_multiplex' => 'graphql.analyze_multiplex',
            'execute_query' => 'graphql.execute_query',
            'execute_query_lazy' => 'graphql.execute_query_lazy',
            'execute_multiplex' => 'graphql.execute_multiplex'
          }

          def platform_trace(platform_key, key, data)
            return yield if platform_key.nil?

            tracer.in_span(platform_key, attributes: attributes_for(key, data)) do |span|
              yield.tap do |response|
                next unless key == 'validate'

                errors = response[:errors]&.compact&.map(&:to_h) || []

                unless errors.empty?
                  span.add_event(
                    'graphql.validation.error',
                    attributes: {
                      'exception.message' => errors.to_json
                    }
                  )
                end
              end
            end
          end

          def platform_field_key(type, field)
            return unless config[:enable_platform_field]

            if config[:legacy_platform_span_names]
              "#{type.graphql_name}.#{field.graphql_name}"
            else
              'graphql.execute_field'
            end
          end

          def platform_authorized_key(type)
            return unless config[:enable_platform_authorized]

            if config[:legacy_platform_span_names]
              "#{type.graphql_name}.authorized"
            else
              'graphql.authorized'
            end
          end

          def platform_resolve_type_key(type)
            return unless config[:enable_platform_resolve_type]

            if config[:legacy_platform_span_names]
              "#{type.graphql_name}.resolve_type"
            else
              'graphql.resolve_type'
            end
          end

          private

          def tracer
            GraphQL::Instrumentation.instance.tracer
          end

          def config
            GraphQL::Instrumentation.instance.config
          end

          def attributes_for(key, data)
            case key
            when 'execute_field'
              field_attr_cache = data[:query].context.namespace(:otel_attrs)[:execute_field_attrs] ||= attr_cache do |field|
                attrs = {}
                attrs['graphql.field.parent'] = field.owner.graphql_name if field.owner.graphql_name
                attrs['graphql.field.name'] = field.graphql_name if field.graphql_name
                attrs['graphql.lazy'] = false
                attrs.freeze
              end
              field_attr_cache[data[:field]]
            when 'execute_field_lazy'
              lazy_field_attr_cache = data[:query].context.namespace(:otel_attrs)[:execute_field_lazy_attrs] ||= attr_cache do |field|
                attrs = {}
                attrs['graphql.field.parent'] = field.owner.graphql_name if field.owner.graphql_name
                attrs['graphql.field.name'] = field.graphql_name if field.graphql_name
                attrs['graphql.lazy'] = true
                attrs.freeze
              end
              lazy_field_attr_cache[data[:field]]
            when 'authorized', 'resolve_type'
              type_attrs_cache = data[:context].namespace(:otel_attrs)[:type_attrs] ||= attr_cache do |type|
                attrs = {}
                attrs['graphql.type.name'] = type.graphql_name if type.graphql_name
                attrs['graphql.lazy'] = false
                attrs.freeze
              end
              type_attrs_cache[data[:type]]
            when 'authorized_lazy', 'resolve_type_lazy'
              type_lazy_attrs_cache = data[:context].namespace(:otel_attrs)[:type_lazy_attrs] ||= attr_cache do |type|
                attrs = {}
                attrs['graphql.type.name'] = type.graphql_name if type.graphql_name
                attrs['graphql.lazy'] = true
                attrs.freeze
              end
              type_lazy_attrs_cache[data[:type]]
            when 'execute_query'
              attrs = {}
              attrs['graphql.document'] = data[:query].query_string if data[:query].query_string
              # rubocop:disable Style/SafeNavigation -- using safe navigation creates more objects, we want to avoid this
              attrs['graphql.operation.type'] = data[:query].selected_operation.operation_type if data[:query].selected_operation && data[:query].selected_operation.operation_type
              # rubocop:enable Style/SafeNavigation
              attrs['graphql.operation.name'] = data[:query].selected_operation_name || 'anonymous'
              attrs.freeze
            else
              DEFAULT_HASH
            end
          end

          def attr_cache
            cache_h = Hash.new do |h, k|
              h[k] = yield(k)
            end
            cache_h.compare_by_identity
            cache_h
          end
        end
      end
    end
  end
end
