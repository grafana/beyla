# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsSdk
      # This handler supports specifically supports V2 and V3
      # prior to Observability support released on 2024-09-03.
      class Handler < Seahorse::Client::Handler
        def call(context)
          return super unless context

          service_id = HandlerHelper.service_id(context, legacy: true)
          client_method = HandlerHelper.client_method(service_id, context)

          tracer.in_span(
            HandlerHelper.span_name(context, client_method, service_id, legacy: true),
            attributes: HandlerHelper.span_attributes(context, client_method, service_id, legacy: true),
            kind: HandlerHelper.span_kind(client_method, service_id)
          ) do |span|
            MessagingHelper.inject_context_if_supported(context, client_method, service_id)

            if HandlerHelper.skip_internal_instrumentation?
              OpenTelemetry::Common::Utilities.untraced { super }
            else
              super
            end.tap do |response|
              span.set_attribute(
                OpenTelemetry::SemanticConventions::Trace::HTTP_STATUS_CODE,
                context.http_response.status_code
              )
              if (err = response.error)
                span.record_exception(err)
                span.status = Trace::Status.error(err.to_s)
              end
            end
          end
        end

        private

        def tracer
          AwsSdk::Instrumentation.instance.tracer
        end
      end

      # A Seahorse::Client::Plugin that enables instrumentation for all AWS services
      class Plugin < Seahorse::Client::Plugin
        def add_handlers(handlers, _config)
          # run before Seahorse::Client::Plugin::ParamValidator (priority 50)
          handlers.add Handler, step: :validate, priority: 49
        end
      end
    end
  end
end
