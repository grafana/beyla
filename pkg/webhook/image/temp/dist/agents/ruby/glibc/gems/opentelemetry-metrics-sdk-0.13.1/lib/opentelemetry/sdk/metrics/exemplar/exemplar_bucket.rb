# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # ExemplarBucket
        # Stores a single exemplar measurement and manages its lifecycle
        class ExemplarBucket
          def initialize
            reset
          end

          # Offers a measurement to be sampled
          #
          # @param value [Numeric] Measured value
          # @param time_unix_nano [Integer] Measurement observation time in nanoseconds
          # @param attributes [Hash] Measurement attributes
          # @param context [Context] Measurement context
          def offer(value:, time_unix_nano:, attributes:, context:)
            @value = value
            @time_unix_nano = time_unix_nano
            @attributes = attributes

            span = ::OpenTelemetry::Trace.current_span(context)
            span_context = span.context
            if span_context.valid?
              @span_id = span_context.span_id
              @trace_id = span_context.trace_id
            end

            @offered = true
          end

          # May return an Exemplar and resets the bucket for the next sampling period
          #
          # @param point_attributes [Hash] Attributes already included in the metric data point
          # @return [Exemplar, nil] The collected exemplar or nil if nothing was offered
          def collect(point_attributes:)
            return nil unless @offered

            filtered_attributes = (@attributes.reject { |k, _v| point_attributes.key?(k) } if @attributes && point_attributes)

            exemplar = Exemplar.new(
              filtered_attributes,
              @value,
              @time_unix_nano,
              @span_id,
              @trace_id
            )

            reset
            exemplar
          end

          private

          # Reset the bucket state after a collection cycle
          def reset
            @value = 0
            @attributes = {}
            @time_unix_nano = 0
            @span_id = nil
            @trace_id = nil
            @offered = false
          end
        end
      end
    end
  end
end
