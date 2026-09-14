# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative 'exponential_histogram/buckets'
require_relative 'exponential_histogram/log2e_scale_factor'
require_relative 'exponential_histogram/ieee_754'
require_relative 'exponential_histogram/logarithm_mapping'
require_relative 'exponential_histogram/exponent_mapping'
require_relative 'exponential_histogram_data_point'

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        # Contains the implementation of the {https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram ExponentialBucketHistogram} aggregation
        class ExponentialBucketHistogram # rubocop:disable Metrics/ClassLength
          # relate to min max scale: https://opentelemetry.io/docs/specs/otel/metrics/sdk/#support-a-minimum-and-maximum-scale
          DEFAULT_SIZE  = 160
          DEFAULT_SCALE = 20
          MAX_SCALE = 20
          MIN_SCALE = -10
          MIN_MAX_SIZE = 2
          MAX_MAX_SIZE = 16_384

          attr_reader :exemplar_reservoir

          # if no reservoir pass from instrument, then use this empty reservoir to avoid no method found error
          DEFAULT_RESERVOIR = Metrics::Exemplar::SimpleFixedSizeExemplarReservoir.new
          private_constant :DEFAULT_RESERVOIR

          # The default boundaries are calculated based on default max_size and max_scale values
          def initialize(
            aggregation_temporality: ENV.fetch('OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE', :delta),
            max_size: DEFAULT_SIZE,
            max_scale: DEFAULT_SCALE,
            record_min_max: true,
            zero_threshold: 0,
            exemplar_reservoir: nil
          )
            @aggregation_temporality = AggregationTemporality.determine_temporality(aggregation_temporality: aggregation_temporality, default: :delta)
            @record_min_max = record_min_max
            @min            = Float::INFINITY
            @max            = -Float::INFINITY
            @sum            = 0
            @count          = 0
            @zero_threshold = zero_threshold
            @zero_count     = 0
            @size           = validate_size(max_size)
            @scale          = validate_scale(max_scale)

            @exemplar_reservoir = exemplar_reservoir || DEFAULT_RESERVOIR
            @exemplar_reservoir_storage = {}

            @mapping = new_mapping(@scale)

            # Previous state for cumulative aggregation
            @previous_positive = {} # nil
            @previous_negative = {} # nil
            @previous_min = {} # Float::INFINITY
            @previous_max = {} # -Float::INFINITY
            @previous_sum = {} # 0
            @previous_count = {} # 0
            @previous_zero_count = {} # 0
            @previous_scale = {} # nil

            # Cache mappings per attribute set
            @mappings = {}
            @previous_mappings = {}
          end

          # when aggregation temporality is cumulative, merge and downscale will happen.
          # rubocop:disable Metrics/MethodLength
          def collect(start_time, end_time, data_points)
            if @aggregation_temporality.delta?
              # Set timestamps and 'move' data point values to result.
              hdps = data_points.values.map! do |hdp|
                hdp.start_time_unix_nano = start_time
                hdp.time_unix_nano = end_time
                reservoir = @exemplar_reservoir_storage[hdp.attributes]
                hdp.exemplars = reservoir&.collect(attributes: hdp.attributes, aggregation_temporality: @aggregation_temporality)
                hdp
              end
              data_points.clear
              @mappings.clear
              hdps
            else
              # CUMULATIVE temporality - merge current data_points to previous data_points
              # and only keep the merged data_points in @previous_*

              merged_data_points = {}

              # this will slow down the operation especially if large amount of data_points present
              # but it should be fine since with cumulative, the data_points are merged into previous_* and not kept in data_points
              # rubocop:disable Metrics/BlockLength
              data_points.each do |attributes, hdp|
                # Store current values
                current_positive = hdp.positive
                current_negative = hdp.negative
                current_sum = hdp.sum
                current_min = hdp.min
                current_max = hdp.max
                current_count = hdp.count
                current_zero_count = hdp.zero_count
                current_scale = hdp.scale

                # Setup previous positive, negative bucket and scale based on three different cases
                @previous_positive[attributes] = current_positive.copy_empty if @previous_positive[attributes].nil?
                @previous_negative[attributes] = current_negative.copy_empty if @previous_negative[attributes].nil?
                @previous_scale[attributes] = current_scale if @previous_scale[attributes].nil?

                # Determine minimum scale for merging
                min_scale = [@previous_scale[attributes], current_scale].min

                # Calculate ranges for positive and negative buckets
                low_positive, high_positive = get_low_high_previous_current(
                  @previous_positive[attributes],
                  current_positive,
                  @previous_scale[attributes],
                  current_scale,
                  min_scale
                )
                low_negative, high_negative = get_low_high_previous_current(
                  @previous_negative[attributes],
                  current_negative,
                  @previous_scale[attributes],
                  current_scale,
                  min_scale
                )

                # Adjust min_scale based on bucket size constraints
                min_scale = [
                  min_scale - get_scale_change(low_positive, high_positive),
                  min_scale - get_scale_change(low_negative, high_negative)
                ].min

                # Downscale previous buckets if necessary
                downscale_change = @previous_scale[attributes] - min_scale
                downscale(downscale_change, @previous_positive[attributes], @previous_negative[attributes])

                # Merge current buckets into previous buckets (kind like update); it's always :cumulative
                merge_buckets(@previous_positive[attributes], current_positive, current_scale, min_scale, @aggregation_temporality)
                merge_buckets(@previous_negative[attributes], current_negative, current_scale, min_scale, @aggregation_temporality)

                # initialize min, max, sum, count, zero_count for first time
                @previous_min[attributes] = Float::INFINITY if @previous_min[attributes].nil?
                @previous_max[attributes] = -Float::INFINITY if @previous_max[attributes].nil?
                @previous_sum[attributes] = 0 if @previous_sum[attributes].nil?
                @previous_count[attributes] = 0 if @previous_count[attributes].nil?
                @previous_zero_count[attributes] = 0 if @previous_zero_count[attributes].nil?

                # Update aggregated values
                @previous_min[attributes] = [@previous_min[attributes], current_min].min
                @previous_max[attributes] = [@previous_max[attributes], current_max].max
                @previous_sum[attributes] += current_sum
                @previous_count[attributes] += current_count
                @previous_zero_count[attributes] += current_zero_count
                @previous_scale[attributes] = min_scale

                # Create merged data point
                reservoir = @exemplar_reservoir_storage[attributes]
                merged_hdp = ExponentialHistogramDataPoint.new(
                  attributes,
                  start_time,
                  end_time,
                  @previous_count[attributes],
                  @previous_sum[attributes],
                  @previous_scale[attributes],
                  @previous_zero_count[attributes],
                  @previous_positive[attributes].dup,
                  @previous_negative[attributes].dup,
                  0, # flags
                  reservoir&.collect(attributes: attributes, aggregation_temporality: @aggregation_temporality), # exemplars
                  @previous_min[attributes],
                  @previous_max[attributes],
                  @zero_threshold
                )

                merged_data_points[attributes] = merged_hdp
                @previous_mappings[attributes] = @mappings[attributes] if @mappings[attributes] # Preserve mapping for next collection
              end
              # rubocop:enable Metrics/BlockLength

              # when you have no local_data_points, the loop from cumulative aggregation will not run
              # so return last merged data points if exists
              if data_points.empty? && !@previous_positive.empty?
                @previous_positive.each_key do |attributes|
                  reservoir = @exemplar_reservoir_storage[attributes]
                  merged_hdp = ExponentialHistogramDataPoint.new(
                    attributes,
                    start_time,
                    end_time,
                    @previous_count[attributes],
                    @previous_sum[attributes],
                    @previous_scale[attributes],
                    @previous_zero_count[attributes],
                    @previous_positive[attributes].dup,
                    @previous_negative[attributes].dup,
                    0, # flags
                    reservoir&.collect(attributes: attributes, aggregation_temporality: @aggregation_temporality), # exemplars
                    @previous_min[attributes],
                    @previous_max[attributes],
                    @zero_threshold
                  )
                  merged_data_points[attributes] = merged_hdp
                end
              end

              # Swap current with previous mappings for next cycle
              @mappings = @previous_mappings
              @previous_mappings = {}

              # clear data_points since the data is merged into previous_* already;
              # otherwise we will have duplicated data_points in the next collect
              data_points.clear
              merged_data_points.values # return array
            end
          end
          # rubocop:enable Metrics/MethodLength

          # this is aggregate in python; there is no merge in aggregate; but rescale happened
          # rubocop:disable Metrics/MethodLength, Metrics/CyclomaticComplexity
          def update(amount, attributes, data_points, exemplar_offer: false)
            # fetch or initialize the ExponentialHistogramDataPoint
            hdp = data_points.fetch(attributes) do
              if @record_min_max
                min = Float::INFINITY
                max = -Float::INFINITY
              end

              # this code block will only be executed if no data_points was found with the attributes
              data_points[attributes] = ExponentialHistogramDataPoint.new(
                attributes,
                nil,                                                               # :start_time_unix_nano
                0,                                                                 # :time_unix_nano
                0,                                                                 # :count
                0,                                                                 # :sum
                @scale,                                                            # :scale
                @zero_count,                                                       # :zero_count
                ExponentialHistogram::Buckets.new,                                 # :positive
                ExponentialHistogram::Buckets.new,                                 # :negative
                0,                                                                 # :flags
                nil,                                                               # :exemplars
                min,                                                               # :min
                max,                                                               # :max
                @zero_threshold                                                    # :zero_threshold
              )
            end

            reservoir = @exemplar_reservoir_storage[attributes]
            unless reservoir
              reservoir = @exemplar_reservoir.dup
              reservoir.reset
              @exemplar_reservoir_storage[attributes] = reservoir
            end

            if exemplar_offer
              reservoir.offer(value: amount,
                              timestamp: OpenTelemetry::Common::Utilities.time_in_nanoseconds,
                              attributes: attributes,
                              context: OpenTelemetry::Context.current)
            end

            # Start to populate the data point (esp. the buckets)
            if @record_min_max
              hdp.max = amount if amount > hdp.max
              hdp.min = amount if amount < hdp.min
            end

            hdp.sum += amount
            hdp.count += 1

            if amount.abs <= @zero_threshold
              hdp.zero_count += 1
              hdp.scale = 0 if hdp.count == hdp.zero_count # if always getting zero, then there is no point to keep doing the update
              return
            end

            # rescale, map to index, update the buckets here
            buckets = amount.positive? ? hdp.positive : hdp.negative
            amount = -amount if amount.negative?

            # Reset scale to max_scale if transitioning from all-zeros to first non-zero value
            if buckets.counts == [0] && hdp.scale == 0 && hdp.count > hdp.zero_count
              hdp.scale = @scale
              @mappings.delete(attributes) # Clear any cached mapping
            end

            # Get or create mapping for this attribute set
            mapping = @mappings[attributes] ||= new_mapping(hdp.scale)
            bucket_index = mapping.map_to_index(amount)

            rescaling_needed = false
            low = high = 0

            if buckets.counts == [0] # special case of empty
              buckets.index_start = bucket_index
              buckets.index_end   = bucket_index
              buckets.index_base  = bucket_index

            elsif bucket_index < buckets.index_start && (buckets.index_end - bucket_index) >= @size
              rescaling_needed = true
              low = bucket_index
              high = buckets.index_end

            elsif bucket_index > buckets.index_end && (bucket_index - buckets.index_start) >= @size
              rescaling_needed = true
              low = buckets.index_start
              high = bucket_index
            end

            if rescaling_needed
              scale_change = get_scale_change(low, high)
              downscale(scale_change, hdp.positive, hdp.negative)
              new_scale = mapping.scale - scale_change
              mapping = new_mapping(new_scale)
              @mappings[attributes] = mapping # Update cache
              bucket_index = mapping.map_to_index(amount)

              OpenTelemetry.logger.debug "Rescaled with new scale #{new_scale} from #{low} and #{high}; bucket_index is updated to #{bucket_index}"
            end

            hdp.scale = mapping.scale

            # adjust buckets based on the bucket_index
            if bucket_index < buckets.index_start
              span = buckets.index_end - bucket_index
              grow_buckets(span, buckets)
              buckets.index_start = bucket_index
            elsif bucket_index > buckets.index_end
              span = bucket_index - buckets.index_start
              grow_buckets(span, buckets)
              buckets.index_end = bucket_index
            end

            bucket_index -= buckets.index_base
            bucket_index += buckets.counts.size if bucket_index.negative?

            buckets.increment_bucket(bucket_index)
            nil
          end
          # rubocop:enable Metrics/MethodLength, Metrics/CyclomaticComplexity

          def aggregation_temporality
            @aggregation_temporality.temporality
          end

          private

          def grow_buckets(span, buckets)
            return if span < buckets.counts.size

            OpenTelemetry.logger.debug "buckets need to grow to #{span + 1} from #{buckets.counts.size} (max bucket size #{@size})"
            buckets.grow(span + 1, @size)
          end

          def new_mapping(scale)
            scale = validate_scale(scale)
            scale <= 0 ? ExponentialHistogram::ExponentMapping.new(scale) : ExponentialHistogram::LogarithmMapping.new(scale)
          end

          def empty_counts
            @boundaries ? Array.new(@boundaries.size + 1, 0) : nil
          end

          def get_scale_change(low, high)
            change = 0
            while high - low >= @size
              high >>= 1
              low >>= 1
              change += 1
            end
            change
          end

          def downscale(change, positive, negative)
            return if change == 0
            raise ArgumentError, 'Invalid change of scale' if change < 0

            positive.downscale(change)
            negative.downscale(change)
          end

          def validate_scale(scale)
            raise ArgumentError, "Scale #{scale} is larger than maximum scale #{MAX_SCALE}" if scale > MAX_SCALE
            raise ArgumentError, "Scale #{scale} is smaller than minimum scale #{MIN_SCALE}" if scale < MIN_SCALE

            scale
          end

          def validate_size(size)
            raise ArgumentError, "Buckets min size #{size} is smaller than minimum min size #{MIN_MAX_SIZE}" if size < MIN_MAX_SIZE
            raise ArgumentError, "Buckets max size #{size} is larger than maximum max size #{MAX_MAX_SIZE}" if size > MAX_MAX_SIZE

            size
          end

          # checked, only issue is if @previous_scale is nil, then get_low_high may throw error
          def get_low_high_previous_current(previous_buckets, current_buckets, previous_scale, current_scale, min_scale)
            previous_low, previous_high = get_low_high(previous_buckets, previous_scale, min_scale)
            current_low, current_high = get_low_high(current_buckets, current_scale, min_scale)

            if current_low > current_high
              [previous_low, previous_high]
            elsif previous_low > previous_high
              [current_low, current_high]
            else
              [[previous_low, current_low].min, [previous_high, current_high].max]
            end
          end

          def get_low_high(buckets, scale, min_scale)
            return [0, -1] if buckets.nil? || buckets.counts == [0] || buckets.counts.empty?

            shift = scale - min_scale
            [buckets.index_start >> shift, buckets.index_end >> shift]
          end

          def merge_buckets(previous_buckets, current_buckets, current_scale, min_scale, aggregation_temporality)
            return unless current_buckets && !current_buckets.counts.empty?

            current_change = current_scale - min_scale

            # when we iterate counts, we don't use offset counts
            current_buckets.instance_variable_get(:@counts).each_with_index do |current_bucket, current_bucket_index|
              next if current_bucket == 0

              current_index = current_buckets.index_base + current_bucket_index
              current_index -= current_buckets.counts.size if current_index > current_buckets.index_end

              inds = current_index >> current_change

              # Grow previous buckets if needed to accommodate the new index
              if inds < previous_buckets.index_start
                span = previous_buckets.index_end - inds

                raise StandardError, 'Incorrect merge scale' if span >= @size

                previous_buckets.grow(span + 1, @size) if span >= previous_buckets.counts.size

                previous_buckets.index_start = inds
              end

              if inds > previous_buckets.index_end
                span = inds - previous_buckets.index_start

                raise StandardError, 'Incorrect merge scale' if span >= @size

                previous_buckets.grow(span + 1, @size) if span >= previous_buckets.counts.size

                previous_buckets.index_end = inds
              end

              bucket_index = inds - previous_buckets.index_base
              bucket_index += previous_buckets.counts.size if bucket_index < 0

              # For delta temporality in merge, we subtract (this shouldn't normally happen in our use case)
              increment = aggregation_temporality == :delta ? -current_bucket : current_bucket
              previous_buckets.increment_bucket(bucket_index, increment)
            end
          end
        end
      end
    end
  end
end
