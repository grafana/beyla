# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Que
      module Middlewares
        # Server middleware to trace Que jobs
        class ServerMiddleware
          def self.call(job, &)
            job_class = job_class(job)
            span_name = "#{job_class} process"
            attributes = attributes_before_job_completion(job, job_class)

            extracted_context = extract_context_from_tags(job.que_attrs[:data][:tags] || [])

            OpenTelemetry::Context.with_current(extracted_context) do
              if otel_config[:propagation_style] == :child
                tracer.in_span(span_name, attributes: attributes, kind: :consumer) do |span|
                  yield
                  enhance_span_after_job_completion(span, job)
                end
              else
                span_links = otel_config[:propagation_style] == :link ? prepare_span_links(extracted_context) : []

                root_span = tracer.start_root_span(span_name, attributes: attributes, links: span_links, kind: :consumer)
                OpenTelemetry::Trace.with_span(root_span) do |span|
                  yield
                  enhance_span_after_job_completion(span, job)
                ensure
                  root_span.finish
                end
              end
            end

            # return value is not important
            nil
          end

          def self.tracer
            OpenTelemetry::Instrumentation::Que::Instrumentation.instance.tracer
          end

          def self.otel_config
            Que::Instrumentation.instance.config
          end

          def self.attributes_before_job_completion(job, job_class)
            attributes = {
              'messaging.system' => 'que',
              'messaging.destination' => job.que_attrs[:queue] || 'default',
              'messaging.destination_kind' => 'queue',
              'messaging.operation' => 'process',
              'messaging.que.job_class' => job_class,
              'messaging.que.priority' => job.que_attrs[:priority] || 100
            }
            attributes['messaging.message_id'] = job.que_attrs[:id] if job.que_attrs[:id]
            attributes
          end

          def self.enhance_span_after_job_completion(span, job)
            span.set_attribute('messaging.que.attempts', job.que_attrs[:error_count])

            error = job.que_error
            return unless error

            span.record_exception(error)
            span.status = OpenTelemetry::Trace::Status.error("Unhandled exception of type: #{error.class}")
          end

          # tags is an array looking something like ["tag1", "traceparent:..."]
          def self.extract_context_from_tags(tags)
            # Convert tags into Hash (ignoring elements that cannot be converted)
            tags_hash = tags.map { |value| value.split(':', 2) }.select { |value| value.size == 2 }.to_h
            OpenTelemetry.propagation.extract(tags_hash)
          end

          def self.job_class(job)
            job.que_attrs[:job_class] || job.class.name
          end

          def self.prepare_span_links(extracted_context)
            span_context = OpenTelemetry::Trace.current_span(extracted_context).context
            span_context.valid? ? [OpenTelemetry::Trace::Link.new(span_context)] : []
          end
        end
      end
    end
  end
end
