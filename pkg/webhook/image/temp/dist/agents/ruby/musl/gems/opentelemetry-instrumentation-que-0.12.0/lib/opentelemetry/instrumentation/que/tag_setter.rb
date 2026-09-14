# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Que
      # The TagSetter class provides methods for writing tracing information to
      # Que tags.
      #
      # @example
      #   OpenTelemetry.propagation.inject(tags, setter: TagSetter)
      class TagSetter
        def self.set(carrier, key, value)
          carrier << "#{key}:#{value}"
        end
      end
    end
  end
end
