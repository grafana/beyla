# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Que
      # The Instrumentation class contains logic to detect and install the Que
      # instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('1.2.0')

        install do |_|
          require_dependencies
          patch

          ::Que.job_middleware.push(Middlewares::ServerMiddleware)
        end

        present do
          defined?(::Que)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        ## Supported configuration keys for the install config hash:
        #
        # propagation_style: controls how the job's execution is traced and related
        #   to the trace where the job was enqueued. Can be one of:
        #
        #   - :link (default) - the job will be executed in a separate trace.
        #     The initial span of the execution trace will be linked to the span
        #     that enqueued the job, via a Span Link.
        #   - :child - the job will be executed in the same logical trace, as a
        #     direct child of the span that enqueued the job.
        #   - :none - the job's execution will not be explicitly linked to the
        #     span that enqueued the job.
        # trace_poller: controls whether Que Poller is traced or not.
        #
        # Note that in all cases, we will store Que's Job ID as the
        # `messaging.message_id` attribute, so out-of-band correlation may
        # still be possible depending on your backend system.
        #
        option :propagation_style, default: :link, validate: %i[link child none]
        option :trace_poller,      default: false, validate: :boolean

        private

        def require_dependencies
          require_relative 'tag_setter'
          require_relative 'middlewares/server_middleware'
          require_relative 'patches/que_job'
          require_relative 'patches/poller'
        end

        def gem_version
          Gem::Version.new(::Que::VERSION)
        end

        def patch
          ::Que::Job.prepend(Patches::QueJob)
          ::Que::Poller.prepend(Patches::Poller)
        end
      end
    end
  end
end
