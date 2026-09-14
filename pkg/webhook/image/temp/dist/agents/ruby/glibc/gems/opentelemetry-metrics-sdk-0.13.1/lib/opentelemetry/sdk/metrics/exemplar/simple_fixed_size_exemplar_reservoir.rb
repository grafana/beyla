# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'etc'

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # SimpleFixedSizeExemplarReservoir uses a uniformly-weighted sampling algorithm based on the number of samples the reservoir has seen so far to determine if the offered measurements should be sampled
        class SimpleFixedSizeExemplarReservoir < ExemplarReservoir
          # Default to number of CPUs for better concurrent performance, fallback to 1
          DEFAULT_SIZE = begin
            Etc.nprocessors
          rescue StandardError
            1
          end

          def initialize(max_size: nil)
            @max_size = max_size || DEFAULT_SIZE
            reset
          end

          # Uses a uniformly-weighted sampling algorithm based on the number of samples the reservoir has seen
          # Fill the buckets array first then randomly override existing bucket
          def offer(value: nil, timestamp: nil, attributes: nil, context: nil)
            bucket_index = find_histogram_bucket
            @exemplar_buckets[bucket_index].offer(value: value, time_unix_nano: timestamp, attributes: attributes, context: context) if bucket_index < @max_size
            @num_measurements_seen += 1
            nil
          end

          # Reset measurement counter on collection for delta temporality
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
            @exemplar_buckets = Array.new(@max_size) { ExemplarBucket.new }
            @num_measurements_seen = 0
          end

          def find_histogram_bucket
            @num_measurements_seen < @max_size ? @num_measurements_seen : rand(0..@num_measurements_seen - 1)
          end
        end
      end
    end
  end
end
