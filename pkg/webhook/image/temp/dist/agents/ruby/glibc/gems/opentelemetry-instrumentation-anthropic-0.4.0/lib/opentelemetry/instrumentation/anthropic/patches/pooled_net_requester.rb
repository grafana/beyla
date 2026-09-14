# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Anthropic
      module Patches
        # Patches Anthropic to propagate context when using PooledNetRequester
        module PooledNetRequester
          OTEL_FIBER_KEY = :_otel_pooled_net_requester_context
          private_constant :OTEL_FIBER_KEY

          def execute(request)
            Fiber[OTEL_FIBER_KEY] = OpenTelemetry::Context.current
            super
          end

          private

          def with_pool(url, deadline:, &blk)
            OpenTelemetry::Context.with_current(Fiber[OTEL_FIBER_KEY]) do
              super
            end
          end
        end
      end
    end
  end
end
