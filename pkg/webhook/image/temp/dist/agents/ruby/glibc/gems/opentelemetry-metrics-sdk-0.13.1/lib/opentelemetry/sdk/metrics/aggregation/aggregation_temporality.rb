# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        # AggregationTemporality represents the temporality of
        # data point ({NumberDataPoint} and {HistogramDataPoint}) in {Metrics}.
        # It determine whether the data point will be cleared for each metrics pull/export.
        class AggregationTemporality
          class << self
            private :new

            # Returns a newly created {AggregationTemporality} with temporality == DELTA
            #
            # @return [AggregationTemporality]
            def delta
              new(DELTA)
            end

            # Returns a newly created {AggregationTemporality} with temporality == CUMULATIVE
            #
            # @return [AggregationTemporality]
            def cumulative
              new(CUMULATIVE)
            end

            # | Preference Value | Counter    | Async Counter    | Histogram  | UpDownCounter | Async UpDownCounter |
            # |------------------|------------|------------------|----------- |---------------|-------------------- |
            # | **Cumulative**   | Cumulative | Cumulative       | Cumulative | Cumulative    | Cumulative          |
            # | **Delta**        | Delta      | Delta            | Delta      | Cumulative    | Cumulative          |
            # | **LowMemory**    | Delta      | Cumulative       | Delta      | Cumulative    | Cumulative          |
            def determine_temporality(aggregation_temporality: nil, instrument_kind: nil, default: nil)
              # aggregation_temporality can't be nil because it always has default value in symbol
              if aggregation_temporality.is_a?(::Symbol)
                aggregation_temporality == :delta ? delta : cumulative

              elsif aggregation_temporality.is_a?(::String)
                case aggregation_temporality
                when 'LOWMEMORY', 'lowmemory', 'low_memory'
                  instrument_kind == :observable_counter ? cumulative : delta
                when 'DELTA', 'delta'
                  delta
                when 'CUMULATIVE', 'cumulative'
                  cumulative
                else
                  default == :delta ? delta : cumulative
                end

              end
            end
          end

          attr_reader :temporality

          # @api private
          # The constructor is private and only for use internally by the class.
          # Users should use the {delta} and {cumulative} factory methods to obtain
          # a {AggregationTemporality} instance.
          #
          # @param [Integer] temporality One of the status codes below
          def initialize(temporality)
            @temporality = temporality
          end

          def delta?
            @temporality == :delta
          end

          def cumulative?
            @temporality == :cumulative
          end

          # delta: data point will be cleared after each metrics pull/export.
          DELTA = :delta

          # cumulative: data point will NOT be cleared after metrics pull/export.
          CUMULATIVE = :cumulative
        end
      end
    end
  end
end
