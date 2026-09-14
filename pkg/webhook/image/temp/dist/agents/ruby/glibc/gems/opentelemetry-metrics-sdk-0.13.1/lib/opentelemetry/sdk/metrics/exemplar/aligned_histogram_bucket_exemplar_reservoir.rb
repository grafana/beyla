# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # AlignedHistogramBucketExemplarReservoir
        #
        # This Exemplar reservoir stores at most one exemplar per histogram bucket.
        # It uses reservoir sampling within each bucket to ensure uniform distribution
        # of exemplars across the value range.
        #
        # This is the recommended reservoir for Explicit Bucket Histogram aggregation.
        class AlignedHistogramBucketExemplarReservoir < ExemplarReservoir
          DEFAULT_BOUNDARIES = [0, 5, 10, 25, 50, 75, 100, 250, 500, 1000].freeze
          private_constant :DEFAULT_BOUNDARIES

          # @param boundaries [Array<Numeric>] The bucket boundaries for the histogram
          def initialize(boundaries: nil)
            @boundaries = boundaries || DEFAULT_BOUNDARIES
            reset
          end

          # Offers a measurement to the reservoir for potential sampling
          #
          # @param value [Numeric] The measurement value
          # @param timestamp [Integer] The timestamp in nanoseconds
          # @param attributes [Hash] The complete set of attributes
          # @param context [Context] The OpenTelemetry context
          def offer(value: nil, timestamp: nil, attributes: nil, context: nil)
            bucket_index = find_histogram_bucket(value)
            @exemplar_buckets[bucket_index].offer(value: value, time_unix_nano: timestamp, attributes: attributes, context: context)
            nil
          end

          # Collects accumulated exemplars and optionally resets state
          #
          # @param attributes [Hash] The attributes to filter from exemplar attributes
          # @param aggregation_temporality [Symbol] :delta or :cumulative
          # @return [Array<Exemplar>] The collected exemplars
          def collect(attributes: nil, aggregation_temporality: nil)
            exemplars = []
            @exemplar_buckets.each do |bucket|
              exemplars << bucket.collect(point_attributes: attributes)
            end
            reset if aggregation_temporality == :delta
            exemplars.compact!
            exemplars
          end

          def reset
            @exemplar_buckets = Array.new(@boundaries.size + 1) { ExemplarBucket.new }
          end

          private

          # Finds the bucket index for a given value
          #
          # @param value [Numeric] The measurement value
          # @return [Integer] The bucket index (0 to boundaries.size)
          def find_histogram_bucket(value)
            @boundaries.bsearch_index { |boundary| boundary >= value } || @boundaries.size
          end
        end
      end
    end
  end
end
