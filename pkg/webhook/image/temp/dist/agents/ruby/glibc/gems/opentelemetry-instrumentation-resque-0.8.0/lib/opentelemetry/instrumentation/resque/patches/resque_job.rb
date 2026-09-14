# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Resque
      module Patches
        # Module to prepend to Resque::Job for instrumentation
        module ResqueJob
          def perform
            job_args = args || []

            # Check if the job is being wrapped by ActiveJob
            # before retrieving the job class name
            job_class = if payload_class_name == 'ActiveJob::QueueAdapters::ResqueAdapter::JobWrapper' && job_args[0].is_a?(Hash)
                          job_args[0]['job_class']
                        else
                          payload_class_name
                        end

            attributes = {
              'messaging.system' => 'resque',
              'messaging.destination' => queue.to_s,
              'messaging.destination_kind' => 'queue',
              'messaging.resque.job_class' => job_class
            }

            span_name = case config[:span_naming]
                        when :job_class then "#{job_class} process"
                        else "#{queue} process"
                        end

            extracted_context = OpenTelemetry.propagation.extract(@payload)

            OpenTelemetry::Context.with_current(extracted_context) do
              if config[:propagation_style] == :child
                tracer.in_span(span_name, attributes: attributes, kind: :consumer) { super }
              else
                links = []
                span_context = OpenTelemetry::Trace.current_span(extracted_context).context
                links << OpenTelemetry::Trace::Link.new(span_context) if config[:propagation_style] == :link && span_context.valid?
                span = tracer.start_root_span(span_name, attributes: attributes, links: links, kind: :consumer)
                OpenTelemetry::Trace.with_span(span) do
                  super
                rescue Exception => e # rubocop:disable Lint/RescueException
                  span.record_exception(e)
                  span.status = OpenTelemetry::Trace::Status.error("Unhandled exception of type: #{e.class}")
                  raise e
                ensure
                  span.finish
                end
              end
            end
          ensure
            if (config[:force_flush] == :ask_the_job && worker&.fork_per_job?) ||
               config[:force_flush] == :always
              OpenTelemetry.tracer_provider.force_flush
            end
          end

          private

          def tracer
            Resque::Instrumentation.instance.tracer
          end

          def config
            Resque::Instrumentation.instance.config
          end
        end
      end
    end
  end
end
