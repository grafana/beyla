# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Logs
      # Class that holds log record attribute limit parameters.
      class LogRecordLimits
        # The global default max number of attributes per {LogRecord}.
        attr_reader :attribute_count_limit

        # The global default max length of attribute value per {LogRecord}.
        attr_reader :attribute_length_limit

        # Returns a {LogRecordLimits} with the desired values.
        #
        # @return [LogRecordLimits] with the desired values.
        # @raise [ArgumentError] if any of the max numbers are not positive.
        def initialize(attribute_count_limit: Integer(OpenTelemetry::Common::Utilities.config_opt(
                                                        'OTEL_LOGRECORD_ATTRIBUTE_COUNT_LIMIT',
                                                        'OTEL_ATTRIBUTE_COUNT_LIMIT',
                                                        default: 128
                                                      )),
                       attribute_length_limit: OpenTelemetry::Common::Utilities.config_opt(
                         'OTEL_LOGRECORD_ATTRIBUTE_VALUE_LENGTH_LIMIT',
                         'OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT'
                       ))
          raise ArgumentError, 'attribute_count_limit must be positive' unless attribute_count_limit.positive?
          raise ArgumentError, 'attribute_length_limit must not be less than 32' unless attribute_length_limit.nil? || Integer(attribute_length_limit) >= 32

          @attribute_count_limit = attribute_count_limit
          @attribute_length_limit = attribute_length_limit.nil? ? nil : Integer(attribute_length_limit)
        end

        # The default {LogRecordLimits}.
        DEFAULT = new
      end
    end
  end
end
