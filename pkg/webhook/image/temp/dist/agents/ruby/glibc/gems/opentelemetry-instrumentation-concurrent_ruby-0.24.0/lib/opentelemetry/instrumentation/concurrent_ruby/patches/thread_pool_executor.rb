# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ConcurrentRuby
      module Patches
        # Concurrent::ThreadPoolExecutor patch for instrumentation
        module ThreadPoolExecutor
          # @see Concurrent::ExecutorService#post
          def post(*args, **kwargs, &)
            context = OpenTelemetry::Context.current
            return super unless context

            super do
              OpenTelemetry::Context.with_current(context) do
                yield(*args, **kwargs)
              end
            end
          end
        end
      end
    end
  end
end
