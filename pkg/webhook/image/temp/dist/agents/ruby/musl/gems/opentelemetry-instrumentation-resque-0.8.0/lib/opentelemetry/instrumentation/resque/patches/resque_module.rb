# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Resque
      module Patches
        # Module to prepend to Resque for instrumentation
        module ResqueModule
          def self.prepended(base)
            class << base
              prepend ClassMethods
            end
          end

          # Module to prepend to Resque singleton class
          module ClassMethods
            def push(queue, item)
              # Check if the job is being wrapped by ActiveJob
              # before retrieving the job class name
              job_class = if item[:class] == 'ActiveJob::QueueAdapters::ResqueAdapter::JobWrapper' && item[:args][0].is_a?(Hash)
                            item[:args][0]['job_class']
                          else
                            item[:class]
                          end

              attributes = {
                'messaging.system' => 'resque',
                'messaging.destination' => queue.to_s,
                'messaging.destination_kind' => 'queue',
                'messaging.resque.job_class' => job_class
              }

              span_name = case config[:span_naming]
                          when :job_class then "#{job_class} publish"
                          else "#{queue} publish"
                          end

              tracer.in_span(span_name, attributes: attributes, kind: :producer) do
                OpenTelemetry.propagation.inject(item)
                super
              end
            end

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
end
