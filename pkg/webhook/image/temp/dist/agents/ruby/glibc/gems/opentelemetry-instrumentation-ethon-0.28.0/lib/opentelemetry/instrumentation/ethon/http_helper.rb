# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Ethon
      # Helper module for HTTP method normalization
      # @api private
      module HttpHelper
        # Lightweight struct to hold span creation attributes
        SpanCreationAttributes = Struct.new(:span_name, :attributes)

        # Pre-computed mapping to avoid string allocations during normalization
        METHOD_CACHE = {
          'CONNECT' => 'CONNECT',
          'DELETE' => 'DELETE',
          'GET' => 'GET',
          'HEAD' => 'HEAD',
          'OPTIONS' => 'OPTIONS',
          'PATCH' => 'PATCH',
          'POST' => 'POST',
          'PUT' => 'PUT',
          'TRACE' => 'TRACE',
          'connect' => 'CONNECT',
          'delete' => 'DELETE',
          'get' => 'GET',
          'head' => 'HEAD',
          'options' => 'OPTIONS',
          'patch' => 'PATCH',
          'post' => 'POST',
          'put' => 'PUT',
          'trace' => 'TRACE',
          :connect => 'CONNECT',
          :delete => 'DELETE',
          :get => 'GET',
          :head => 'HEAD',
          :options => 'OPTIONS',
          :patch => 'PATCH',
          :post => 'POST',
          :put => 'PUT',
          :trace => 'TRACE'
        }.freeze

        private_constant :METHOD_CACHE

        OLD_SPAN_NAMES_BY_METHOD = METHOD_CACHE.values.uniq.to_h do |method|
          [method, "HTTP #{method}"]
        end.freeze

        private_constant :OLD_SPAN_NAMES_BY_METHOD

        # Prepares span data using old semantic conventions
        # @param method [String, Symbol] The HTTP method
        # @return [SpanCreationAttributes] struct containing span_name and attributes hash
        def self.span_attrs_for_old(method)
          client_context_attrs = OpenTelemetry::Common::HTTP::ClientContext.attributes
          normalized = METHOD_CACHE[method]
          attributes = client_context_attrs.dup

          # Determine base span name and method value
          if normalized
            span_name = OLD_SPAN_NAMES_BY_METHOD[normalized]
            method_value = normalized
          else
            span_name = 'HTTP'
            method_value = '_OTHER'
          end

          attributes['http.method'] ||= method_value

          SpanCreationAttributes.new(span_name: span_name, attributes: attributes)
        end

        # Prepares span data using stable semantic conventions
        # @param method [String, Symbol] The HTTP method
        # @return [SpanCreationAttributes] struct containing span_name and attributes hash
        def self.span_attrs_for_stable(method)
          client_context_attrs = OpenTelemetry::Common::HTTP::ClientContext.attributes
          url_template = client_context_attrs['url.template']
          normalized = METHOD_CACHE[method]
          attributes = client_context_attrs.dup

          # Determine base span name and method value
          if normalized
            base_name = normalized
            method_value = normalized
            original = nil
          else
            base_name = 'HTTP'
            method_value = '_OTHER'
            original = method.to_s
          end

          span_name = url_template ? "#{base_name} #{url_template}" : base_name
          attributes['http.request.method'] ||= method_value
          attributes['http.request.method_original'] ||= original if original

          SpanCreationAttributes.new(span_name: span_name, attributes: attributes)
        end

        # Prepares span data using both old and stable semantic conventions
        # @param method [String, Symbol] The HTTP method
        # @return [SpanCreationAttributes] struct containing span_name and attributes hash
        def self.span_attrs_for_dup(method)
          client_context_attrs = OpenTelemetry::Common::HTTP::ClientContext.attributes
          url_template = client_context_attrs['url.template']
          normalized = METHOD_CACHE[method]
          attributes = client_context_attrs.dup

          # Determine base span name and method value
          if normalized
            base_name = normalized
            method_value = normalized
            original = nil
          else
            base_name = 'HTTP'
            method_value = '_OTHER'
            original = method.to_s
          end

          span_name = url_template ? "#{base_name} #{url_template}" : base_name
          attributes['http.method'] ||= method_value
          attributes['http.request.method'] ||= method_value
          attributes['http.request.method_original'] ||= original if original

          SpanCreationAttributes.new(span_name: span_name, attributes: attributes)
        end
      end
    end
  end
end
