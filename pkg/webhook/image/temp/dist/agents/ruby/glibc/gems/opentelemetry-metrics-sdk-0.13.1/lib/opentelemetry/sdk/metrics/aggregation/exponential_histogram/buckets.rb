# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Aggregation
        module ExponentialHistogram
          # Buckets is the fundamental building block of exponential histogram that store bucket/boundary value
          class Buckets
            attr_accessor :index_start, :index_end, :index_base

            def initialize
              @counts = [0]
              @index_base = 0
              @index_start = 0
              @index_end = 0
            end

            # grow simply expand the @counts size
            def grow(needed, max_size)
              size = @counts.size
              bias = @index_base - @index_start
              old_positive_limit = size - bias

              new_size = [2**Math.log2(needed).ceil, max_size].min
              new_positive_limit = new_size - bias

              tmp = Array.new(new_size, 0)
              tmp[new_positive_limit..-1] = @counts[old_positive_limit..]
              tmp[0...old_positive_limit] = @counts[0...old_positive_limit]
              @counts = tmp
            end

            def offset
              @index_start
            end

            def offset_counts
              bias = @index_base - @index_start
              @counts[-bias..] + @counts[0...-bias]
            end
            alias counts offset_counts

            def length
              return 0 if @counts.empty?
              return 0 if @index_end == @index_start && counts[0] == 0

              @index_end - @index_start + 1
            end

            def get_bucket(key)
              bias = @index_base - @index_start

              key += @counts.size if key < bias
              key -= bias

              @counts[key]
            end

            def downscale(amount)
              bias = @index_base - @index_start

              if bias != 0
                @index_base = @index_start
                @counts.reverse!
                @counts = @counts[0...bias].reverse + @counts[bias..].reverse
              end

              size = 1 + @index_end - @index_start
              each = 1 << amount
              inpos = 0
              outpos = 0
              pos = @index_start

              while pos <= @index_end
                mod = pos % each
                mod += each if mod < 0

                inds = mod

                while inds < each && inpos < size
                  if outpos != inpos
                    @counts[outpos] += @counts[inpos]
                    @counts[inpos] = 0
                  end

                  inpos += 1
                  pos   += 1
                  inds  += 1
                end

                outpos += 1
              end

              @index_start >>= amount
              @index_end >>= amount
              @index_base = @index_start
            end

            def increment_bucket(bucket_index, increment = 1)
              @counts[bucket_index] += increment
            end

            def copy_empty
              new_buckets = self.class.new
              new_buckets.instance_variable_set(:@counts, Array.new(@counts.size, 0))
              new_buckets.instance_variable_set(:@index_base, @index_base)
              new_buckets.instance_variable_set(:@index_start, @index_start)
              new_buckets.instance_variable_set(:@index_end, @index_end)
              new_buckets
            end
          end
        end
      end
    end
  end
end
