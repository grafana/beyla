# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Que
      module Patches
        # Instrumentation for the Que::Poller module
        module Poller
          def poll(*args, **kwargs)
            # Avoid tracing when should_poll? returns true. This is also used
            # in Poller#poll to decide if the actual poll should be executed or
            # not. Without this we would generate a lot of unnecessary spans.
            return unless should_poll?

            if Que::Instrumentation.instance.config[:trace_poller]
              Que::Instrumentation.instance.tracer.in_span('Que::Poller#poll') { super }
            else
              OpenTelemetry::Common::Utilities.untraced { super }
            end
          end
        end
      end
    end
  end
end
