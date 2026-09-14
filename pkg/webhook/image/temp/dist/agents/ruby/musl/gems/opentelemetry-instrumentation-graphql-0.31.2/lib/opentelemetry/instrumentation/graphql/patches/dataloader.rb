# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module GraphQL
      module Patches
        # Patches GraphQL::Dataloader to propagate context to new fiber
        module Dataloader
          def spawn_fiber(&block)
            ctx = OpenTelemetry::Context.current
            super do
              OpenTelemetry::Context.with_current(ctx, &block)
            end
          end
        end
      end
    end
  end
end
