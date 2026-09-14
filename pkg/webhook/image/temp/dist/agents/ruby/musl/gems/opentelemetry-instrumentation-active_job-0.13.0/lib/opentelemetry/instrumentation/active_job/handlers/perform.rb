# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveJob
      module Handlers
        # Handles perform.active_job to generate ingress spans
        class Perform < Default
          EVENT_NAME = 'process'

          # Overrides the `Default#start_span` method to create an ingress span
          # and registers it with the current context
          #
          # @param name [String] of the Event
          # @param id [String] of the event
          # @param payload [Hash] containing job run information
          # @return [Hash] with the span and generated context tokens
          def start_span(name, _id, payload)
            job = payload.fetch(:job)
            span_name = span_name(job, EVENT_NAME)
            parent_context = OpenTelemetry.propagation.extract(job.__otel_headers)

            # TODO: Refactor into a propagation strategy
            propagation_style = @config[:propagation_style]
            if propagation_style == :child
              span = tracer.start_span(span_name, with_parent: parent_context, kind: :consumer, attributes: @mapper.call(payload))
            else
              span_context = OpenTelemetry::Trace.current_span(parent_context).context
              links = [OpenTelemetry::Trace::Link.new(span_context)] if span_context.valid? && propagation_style == :link
              span = tracer.start_root_span(span_name, kind: :consumer, attributes: @mapper.call(payload), links: links)
            end

            { span: span, ctx_token: attach_consumer_context(span, parent_context) }
          end

          # This method attaches a span to multiple contexts:
          # 1. Registers the ingress span as the top level ActiveJob span.
          #    This is used later to enrich the ingress span in children, e.g. setting span status to error when a child event like `discard` terminates due to an error
          # 2. Registers the ingress span as the "active" span, which is the default behavior of the SDK.
          # @param span [OpenTelemetry::Trace::Span] the currently active span used to record the exception and set the status
          # @param parent_context [Context] The context to use as the parent for the consumer context
          # @return [Numeric] Context token that must be detached when finished
          def attach_consumer_context(span, parent_context)
            consumer_context = OpenTelemetry::Trace.context_with_span(span, parent_context: parent_context)
            internal_context = OpenTelemetry::Instrumentation::ActiveJob.context_with_span(span, parent_context: consumer_context)

            OpenTelemetry::Context.attach(internal_context)
          end
        end
      end
    end
  end
end
