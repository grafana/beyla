# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Sidekiq
      module Patches
        # The Launcher module contains the instrumentation for the Sidekiq heartbeat
        module Launcher
          private

          def ❤ # rubocop:disable Naming/MethodName, Naming/AsciiIdentifiers
            if instrumentation_config[:trace_launcher_heartbeat]
              attributes = {}
              attributes[SemanticConventions::Trace::PEER_SERVICE] = instrumentation_config[:peer_service] if instrumentation_config[:peer_service]
              tracer.in_span('Sidekiq::Launcher#heartbeat', attributes: attributes) { super }
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
