# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsSdk
      module Patches
        # Patch for Telemetry Plugin Handler in V3 SDK
        module Handler
          def call(context)
            span_wrapper(context) { @handler.call(context) }
          end

          private

          def span_wrapper(context, &)
            service_id = HandlerHelper.service_id(context)
            client_method = HandlerHelper.client_method(service_id, context)
            context.tracer.in_span(
              HandlerHelper.span_name(context, client_method, service_id),
              attributes: HandlerHelper.span_attributes(context, client_method, service_id),
              kind: HandlerHelper.span_kind(client_method, service_id)
            ) do |span|
              MessagingHelper.inject_context_if_supported(context, client_method, service_id)

              if HandlerHelper.skip_internal_instrumentation?
                OpenTelemetry::Common::Utilities.untraced { super }
              else
                yield span
              end
            end
          end
        end
      end
    end
  end
end
