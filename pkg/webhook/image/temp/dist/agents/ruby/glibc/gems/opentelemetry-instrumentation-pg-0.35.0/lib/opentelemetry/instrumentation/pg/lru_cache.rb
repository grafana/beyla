# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module PG
      # A simple LRU cache for the postgres instrumentation.
      class LruCache
        # Rather than take a dependency on another gem, we implement a very, very basic
        # LRU cache here. We can take advantage of the fact that Ruby hashes are ordered
        # to always keep the recently-accessed keys at the top.
        def initialize(size)
          raise ArgumentError, 'Invalid size' if size < 1

          @limit = size
          @store = {}
        end

        def [](key)
          # We need to check for the key explicitly, because `nil` is a valid hash value.
          return unless @store.key?(key)

          # Since the cache contains the item, we delete and re-insert into the hash.
          # This guarantees that hash keys are ordered by access recency.
          value = @store.delete(key)
          @store[key] = value

          value
        end

        def []=(key, value)
          # We remove the value if it's already present, so that the hash keys remain ordered
          # by access recency.
          @store.delete(key)
          @store[key] = value
          @store.shift if @store.length > @limit
        end
      end
    end
  end
end
