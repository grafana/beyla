# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Sidekiq
      module Patches
        # The Poller module contains instrumentation for the enqueue and wait methods
        module Poller
          def enqueue
            if instrumentation_config[:trace_poller_enqueue]
              attributes = {}
              attributes[SemanticConventions::Trace::PEER_SERVICE] = instrumentation_config[:peer_service] if instrumentation_config[:peer_service]
              tracer.in_span('Sidekiq::Scheduled::Poller#enqueue', attributes: attributes) { super }
            else
              OpenTelemetry::Common::Utilities.untraced { super }
            end
          end

          private

          def wait
            if instrumentation_config[:trace_poller_wait]
              tracer.in_span('Sidekiq::Scheduled::Poller#wait') { super }
            else
              OpenTelemetry::Common::Utilities.untraced { super }
            end
          end

          def tracer
            Sidekiq::Instrumentation.instance.tracer
          end

          def instrumentation_config
            Sidekiq::Instrumentation.instance.config
          end
        end
      end
    end
  end
end
