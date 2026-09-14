# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Que
      module Patches
        # Module to prepend to Que::Job for instrumentation
        module QueJob
          def self.prepended(base)
            class << base
              prepend ClassMethods
            end
          end

          # Module to prepend to Que singleton class
          module ClassMethods
            def enqueue(*args, job_options: {}, **arg_opts)
              # In Que version 2.1.0 `bulk_enqueue` was introduced.
              # In that case, the span is created inside the `bulk_enqueue` method.
              return super(*args, **arg_opts) if gem_version >= Gem::Version.new('2.1.0') && Thread.current[:que_jobs_to_bulk_insert]

              tracer = Que::Instrumentation.instance.tracer
              otel_config = Que::Instrumentation.instance.config

              tracer.in_span('publish', kind: :producer) do |span|
                # Que doesn't have a good place to store metadata. There are
                # basically two options: the job payload and the job tags.
                #
                # Using the job payload is very brittle. We'd have to modify
                # existing Hash arguments or add a new argument when there are
                # no arguments we can modify. If the server side is not using
                # this instrumentation yet (e.g. old jobs before the
                # instrumentation was added or when instrumentation is being
                # added to client side first) then the server can error out due
                # to unexpected payload.
                #
                # The second option (which we are using here) is to use tags.
                # They also are not meant for tracing information but they are
                # much safer to use than modifying the payload.
                tags = job_options[:tags]
                if otel_config[:propagation_style] != :none
                  tags ||= []
                  OpenTelemetry.propagation.inject(tags, setter: TagSetter)
                end

                job = super(*args, job_options: job_options.merge(tags: tags), **arg_opts)
                job_attrs = job.que_attrs

                span.name = "#{job_attrs[:job_class]} publish"
                span.add_attributes(QueJob.job_attributes(job_attrs))

                job
              end
            end

            def gem_version
              @gem_version ||= Gem.loaded_specs['que'].version
            end

            if Gem.loaded_specs['que'].version >= Gem::Version.new('2.1.0')
              def bulk_enqueue(**_kwargs, &)
                tracer = Que::Instrumentation.instance.tracer
                otel_config = Que::Instrumentation.instance.config

                tracer.in_span('publish', kind: :producer) do |span|
                  super do
                    yield

                    job_attrs = Thread.current[:que_jobs_to_bulk_insert][:jobs_attrs]

                    unless job_attrs.empty?
                      span.name = "#{job_attrs.first[:job_class]} publish"
                      span.add_attributes(QueJob.job_attributes(job_attrs.first))
                    end

                    if otel_config[:propagation_style] != :none
                      job_options = Thread.current[:que_jobs_to_bulk_insert][:job_options]
                      job_options[:tags] ||= []
                      OpenTelemetry.propagation.inject(job_options[:tags], setter: TagSetter)
                    end
                  end
                end
              end
            end
          end

          def self.job_attributes(job_attrs)
            attributes = {
              'messaging.system' => 'que',
              'messaging.destination_kind' => 'queue',
              'messaging.operation' => 'publish',
              'messaging.destination' => job_attrs[:queue] || 'default',
              'messaging.que.job_class' => job_attrs[:job_class],
              'messaging.que.priority' => job_attrs[:priority] || 100
            }
            attributes['messaging.message_id'] = job_attrs[:id] if job_attrs[:id]
            attributes
          end
        end
      end
    end
  end
end
