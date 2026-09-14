# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Resque
      # The {OpenTelemetry::Instrumentation::Resque::Instrumentation} class contains logic to detect and install the Resque instrumentation
      #
      # Installation and configuration of this instrumentation is done within the
      # {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry/SDK#configure-instance_method OpenTelemetry::SDK#configure}
      # block, calling {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use use()}
      # or {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use_all use_all()}.
      #
      # ## Configuration keys and options
      #
      # ### `:span_naming`
      #
      # Specifies how the span names are set. Can be one of:
      #
      # - `:queue` **(default)** - The job span name will appear as '<destination / queue name> <operation>',
      #   for example `default process`.
      # - `:job_class` - The job span name will appear as '<job class name> <operation>',
      #   for example `SimpleJob process`.
      #
      # ### `:propagation_style`
      #
      # Specifies how the job's execution is traced and related to the trace where the job was enqueued.
      #
      # - `:link` **(default)** - The job will be represented by a separate trace from the span that enqueued the job.
      #     - The initial span of the job trace will be associated with the span that enqueued the job, via a
      #       {https://opentelemetry.io/docs/concepts/signals/traces/#span-links Span Link}.
      # - `:child` - The job will be represented within the same logical trace, as a direct
      #   child of the span that enqueued the job.
      # - `:none` - The job will be represented by a separate trace from the span that enqueued the job.
      #   There will be no explicit relationship between the job trace and the trace containing the span that
      #   enqueued the job.
      #
      # ### `:force_flush`
      #
      # Specifies whether spans are forcibly flushed (exported out of process) upon every job completion.
      #
      #   - `:ask_the_job` **(default)** - Synchronously flush completed spans when a job completes if workers are
      #     forked for each job.
      #       - Determined by checking if {https://www.rubydoc.info/gems/resque/Resque%2FWorker:fork_per_job%3F Resque::Worker#fork_per_job?}
      #         is true. Spans must be flushed and exported before a worker process terminates or no telemetry will be sent.
      #   - `:always` - All completed spans will be synchronously flushed at the end of a job's execution.
      #   - `:never` - Job completion will not affect the export of spans out of worker processes.
      #       - Selecting this option will result in spans being lost if the worker process ends before
      #         the spans are flushed. You might select this option if you wish to coordinate the timing for flushing
      #         completed spans yourself.
      #
      # @example An explicit default configuration
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use_all({
      #       'OpenTelemetry::Instrumentation::Resque' => {
      #         span_naming: :queue,
      #         propagation_style: :link
      #         force_flush: :ask_the_job,
      #       },
      #     })
      #   end
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          require_dependencies
          patch
        end

        present do
          defined?(::Resque)
        end

        option :force_flush,       default: :ask_the_job, validate: %I[ask_the_job always never]
        option :span_naming,       default: :queue,       validate: %I[job_class queue]
        option :propagation_style, default: :link,        validate: %i[link child none]

        private

        def patch
          ::Resque.prepend(Patches::ResqueModule)
          ::Resque::Job.prepend(Patches::ResqueJob)
        end

        def require_dependencies
          require_relative 'patches/resque_module'
          require_relative 'patches/resque_job'
        end
      end
    end
  end
end
