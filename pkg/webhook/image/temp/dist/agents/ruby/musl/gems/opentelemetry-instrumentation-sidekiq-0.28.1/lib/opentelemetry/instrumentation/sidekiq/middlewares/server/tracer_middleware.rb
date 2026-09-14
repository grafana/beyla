# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Sidekiq
      module Middlewares
        module Server
          # TracerMiddleware propagates context and instruments Sidekiq requests
          # by way of its middleware system
          class TracerMiddleware
            include ::Sidekiq::ServerMiddleware if defined?(::Sidekiq::ServerMiddleware)

            def call(_worker, msg, _queue)
              attributes = {
                SemanticConventions::Trace::MESSAGING_SYSTEM => 'sidekiq',
                'messaging.sidekiq.job_class' => msg['wrapped']&.to_s || msg['class'],
                SemanticConventions::Trace::MESSAGING_MESSAGE_ID => msg['jid'],
                SemanticConventions::Trace::MESSAGING_DESTINATION => msg['queue'],
                SemanticConventions::Trace::MESSAGING_DESTINATION_KIND => 'queue',
                SemanticConventions::Trace::MESSAGING_OPERATION => 'process'
              }
              attributes[SemanticConventions::Trace::PEER_SERVICE] = instrumentation_config[:peer_service] if instrumentation_config[:peer_service]

              span_name = case instrumentation_config[:span_naming]
                          when :job_class then "#{msg['wrapped']&.to_s || msg['class']} process"
                          else "#{msg['queue']} process"
                          end

              extracted_context = OpenTelemetry.propagation.extract(msg)
              OpenTelemetry::Context.with_current(extracted_context) do
                if instrumentation_config[:propagation_style] == :child
                  tracer.in_span(span_name, attributes: attributes, kind: :consumer) do |span|
                    add_span_timestamps(span, msg)
                    yield
                  end
                else
                  links = []
                  span_context = OpenTelemetry::Trace.current_span(extracted_context).context
                  links << OpenTelemetry::Trace::Link.new(span_context) if instrumentation_config[:propagation_style] == :link && span_context.valid?
                  span = tracer.start_root_span(span_name, attributes: attributes, links: links, kind: :consumer)
                  OpenTelemetry::Trace.with_span(span) do
                    add_span_timestamps(span, msg)
                    yield
                  rescue Exception => e # rubocop:disable Lint/RescueException
                    span.record_exception(e)
                    span.status = OpenTelemetry::Trace::Status.error("Unhandled exception of type: #{e.class}")
                    raise e
                  ensure
                    span.finish
                  end
                end
              end
            end

            private

            def instrumentation_config
              Sidekiq::Instrumentation.instance.config
            end

            def tracer
              Sidekiq::Instrumentation.instance.tracer
            end

            def add_span_timestamps(span, msg)
              created_at = msg['created_at']
              enqueued_at = msg['enqueued_at']
              span.add_event('created_at', timestamp: time_from_timestamp(created_at)) if created_at
              span.add_event('enqueued_at', timestamp: time_from_timestamp(enqueued_at)) if enqueued_at
            end

            def time_from_timestamp(timestamp)
              if timestamp.is_a?(Float)
                # old format, timestamps were stored as fractional seconds since the epoch
                timestamp
              else
                timestamp/1000r
              end
            end
          end
        end
      end
    end
  end
end
