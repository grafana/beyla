# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Metrics
    module Instrument
      # No-op implementation of UpDownCounter.
      class UpDownCounter
        # Increment or decrement the UpDownCounter by a fixed amount.
        #
        # @param [Numeric] amount The amount to be added, can be positive, negative or zero.
        # @param [Hash{String => String, Numeric, Boolean, Array<String, Numeric, Boolean>}] attributes
        #   Values must be non-nil and (array of) string, boolean or numeric type.
        #   Array values must not contain nil elements and all elements must be of
        #   the same basic type (string, numeric, boolean).
        def add(amount, attributes: {}); end
      end
    end
  end
end
