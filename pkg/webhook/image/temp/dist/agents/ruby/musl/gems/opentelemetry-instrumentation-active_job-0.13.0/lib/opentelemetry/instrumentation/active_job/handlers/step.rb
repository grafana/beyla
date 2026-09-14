# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveJob
      module Handlers
        # Handles step.active_job to generate child spans for continuable job steps
        class Step < Default
          # Overrides the `Default#start_span` method to create a child span
          # for a continuable job step
          #
          # @param name [String] of the Event
          # @param id [String] of the event
          # @param payload [Hash] containing job run information
          # @return [Hash] with the span and generated context tokens
          def start_span(name, _id, payload)
            job = payload.fetch(:job)
            job_name = job.class.name
            step = payload.fetch(:step)
            step_name = step.name.to_s

            attributes = @mapper.call(payload).merge(
              'messaging.active_job.step.name' => step_name,
              'messaging.active_job.step.state' => step.resumed? ? 'resumed' : 'started'
            )

            span = tracer.start_span("#{step_name} #{job_name}", attributes: attributes)
            token = OpenTelemetry::Context.attach(OpenTelemetry::Trace.context_with_span(span))

            { span: span, ctx_token: token }
          end

          # Overrides the `Default#finish` method to record step-specific
          # attributes before closing the span
          #
          # @param _name [String] of the Event (unused)
          # @param _id [String] of the event (unused)
          # @param payload [Hash] containing job run information
          def finish(_name, _id, payload)
            otel = payload.delete(:__otel)
            span = otel&.fetch(:span)
            token = otel&.fetch(:ctx_token)

            step = payload.fetch(:step)
            span&.set_attribute('messaging.active_job.step.result', 'interrupted') if payload[:interrupted]
            span&.set_attribute('messaging.active_job.step.cursor', step.cursor.to_s) if step.cursor

            # Continuation::Interrupt is control flow, not a real error — skip recording it
            on_exception(payload[:error] || payload[:exception_object], span) unless payload[:interrupted]
          rescue StandardError => e
            OpenTelemetry.handle_error(exception: e)
          ensure
            finish_span(span, token)
          end
        end
      end
    end
  end
end
