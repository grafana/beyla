# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module View
        # RegisteredView is an internal class used to match Views with a given {MetricStream}
        class RegisteredView
          attr_reader :name, :aggregation, :attribute_keys, :regex

          def initialize(name, **options)
            @name = name
            @options = options
            @aggregation = options[:aggregation]
            @attribute_keys = options[:attribute_keys] || {}

            generate_regex_pattern(name)
          end

          def match_instrument?(metric_stream)
            return false if @name && !name_match(metric_stream.name)
            return false if @options[:type] && @options[:type] != metric_stream.instrument_kind
            return false if @options[:unit] && @options[:unit] != metric_stream.unit
            return false if @options[:meter_name] && @options[:meter_name] != metric_stream.instrumentation_scope.name
            return false if @options[:meter_version] && @options[:meter_version] != metric_stream.instrumentation_scope.version

            true
          end

          def name_match(stream_name)
            !!@regex&.match(stream_name)
          end

          def valid_aggregation?
            @aggregation.class.name.rpartition('::')[0] == 'OpenTelemetry::SDK::Metrics::Aggregation'
          end

          private

          def generate_regex_pattern(view_name)
            regex_pattern = Regexp.escape(view_name)

            regex_pattern.gsub!('\*', '.*')
            regex_pattern.gsub!('\?', '.')

            @regex = Regexp.new("^#{regex_pattern}$")
          rescue StandardError
            @regex = nil
          end
        end
      end
    end
  end
end
