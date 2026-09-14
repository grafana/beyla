# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveJob
      # The Instrumentation class contains logic to detect and install the ActiveJob instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('7.1')

        install do |_config|
          require_dependencies
          patch_activejob
        end

        present do
          defined?(::ActiveJob) && defined?(::ActiveSupport)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        ## Supported configuration keys for the install config hash:
        #
        # span_naming: when `:job_class`, the span names will be set to
        #   '<job class name> <operation>'. When `:queue`, the span names
        #   will be set to '<destination / queue name> <operation>'
        #
        # force_flush: when `true`, all completed spans will be synchronously flushed
        #   at the end of a job's execution (default: `false`). You will likely wish to
        #   enable this option for job systems that fork worker processes such as Resque.
        #
        # propagation_style: controls how the job's execution is traced and related
        #   to the trace where the job was enqueued. Can be one of:
        #
        #   - :link (default) - the job will be executed in a separate trace. The
        #     initial span of the execution trace will be linked to the span that
        #     enqueued the job, via a Span Link.
        #   - :child - the job will be executed in the same logical trace, as a direct
        #     child of the span that enqueued the job.
        #   - :none - the job's execution will not be explicitly linked to the span that
        #     enqueued the job.
        #
        # Note that in all cases, we will store ActiveJob's Job ID as the `messaging.message_id`
        # attribute, so out-of-band correlation may still be possible depending on your backend system.
        #
        # Note that when using the `:inline` ActiveJob queue adapter, then execution
        # spans will always be children of the enqueueing spans. This is due to the way
        # ActiveJob immediately executes jobs during the process of "enqueueing" jobs when
        # using the `:inline` adapter.
        option :propagation_style, default: :link, validate: %i[link child none]
        option :force_flush, default: false, validate: :boolean
        option :span_naming, default: :queue, validate: %i[job_class queue]

        private

        def gem_version
          ::ActiveJob.version
        end

        def require_dependencies
          require 'active_support/lazy_load_hooks'
          require_relative 'patches/base'
          require_relative 'handlers'
        end

        def patch_activejob
          Handlers.subscribe

          ::ActiveSupport.on_load(:active_job) do
            ::ActiveJob::Base.prepend(Patches::Base) unless ::ActiveJob::Base <= Patches::Base
          end
        end
      end
    end
  end
end
