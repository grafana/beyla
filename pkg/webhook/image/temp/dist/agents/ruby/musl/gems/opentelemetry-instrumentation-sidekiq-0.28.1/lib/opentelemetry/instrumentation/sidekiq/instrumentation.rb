# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Sidekiq
      # The `OpenTelemetry::Instrumentation::Sidekiq::Instrumentation` class contains logic to detect and install the Sidekiq instrumentation
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
      # ### `:trace_launcher_heartbeat`
      #
      # Allows tracing Sidekiq::Launcher#heartbeat.
      #
      # - `false` **(default)** - Sidekiq::Launcher#heartbeat will not be traced.
      # - `true` - Sidekiq::Launcher#heartbeat will be traced.
      #
      # ### `:trace_poller_enqueue`
      #
      # Allows tracing Sidekiq::Scheduled#enqueue.
      #
      # - `false` **(default)** - Sidekiq::Scheduled#enqueue will not be traced.
      # - `true` - Sidekiq::Scheduled#enqueue will be traced.
      #
      # ### `:trace_poller_wait`
      #
      # Allows tracing Sidekiq::Scheduled#wait.
      #
      # - `false` **(default)** - Sidekiq::Scheduled#wait will not be traced.
      # - `true` - Sidekiq::Scheduled#wait will be traced.
      #
      # ### `:trace_processor_process_one`
      #
      # Allows tracing Sidekiq::Processor#process_one.
      #
      # - `false` **(default)** - Sidekiq::Processor#process_one will not be traced.
      # - `true` - Sidekiq::Processor#process_one will be traced.
      #
      # ### `:peer_service`
      #
      # Sets service name of the remote service.
      #
      # - `nil` **(default)**
      #
      # @example An explicit default configuration
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use_all({
      #       'OpenTelemetry::Instrumentation::Sidekiq' => {
      #         span_naming: :queue,
      #         propagation_style: :link,
      #         trace_launcher_heartbeat: true,
      #       },
      #     })
      #   end
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('4.2.10')

        install do |_config|
          require_dependencies
          add_client_middleware
          add_server_middleware
          patch_on_startup
        end

        present do
          defined?(::Sidekiq)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        option :span_naming,                 default: :queue, validate: %I[job_class queue]
        option :propagation_style,           default: :link,  validate: %i[link child none]
        option :trace_launcher_heartbeat,    default: false, validate: :boolean
        option :trace_poller_enqueue,        default: false, validate: :boolean
        option :trace_poller_wait,           default: false, validate: :boolean
        option :trace_processor_process_one, default: false, validate: :boolean
        option :peer_service,                default: nil,   validate: :string

        private

        def gem_version
          Gem::Version.new(::Sidekiq::VERSION)
        end

        def require_dependencies
          require_relative 'middlewares/client/tracer_middleware'
          require_relative 'middlewares/server/tracer_middleware'

          require_relative 'patches/processor'
          require_relative 'patches/launcher'
          require_relative 'patches/poller'
        end

        def patch_on_startup
          ::Sidekiq.configure_server do |config|
            config.on(:startup) do
              ::Sidekiq::Processor.prepend(Patches::Processor)
              ::Sidekiq::Launcher.prepend(Patches::Launcher)
              ::Sidekiq::Scheduled::Poller.prepend(Patches::Poller)
            end

            config.on(:shutdown) do
              OpenTelemetry.tracer_provider.shutdown
            end
          end
        end

        def add_client_middleware
          ::Sidekiq.configure_client do |config|
            config.client_middleware do |chain|
              chain.prepend Middlewares::Client::TracerMiddleware
            end
          end
        end

        def add_server_middleware
          ::Sidekiq.configure_server do |config|
            config.client_middleware do |chain|
              chain.prepend Middlewares::Client::TracerMiddleware
            end
            config.server_middleware do |chain|
              chain.prepend Middlewares::Server::TracerMiddleware
            end
          end

          if defined?(::Sidekiq::Testing) # rubocop:disable Style/GuardClause
            ::Sidekiq::Testing.server_middleware do |chain|
              chain.prepend Middlewares::Server::TracerMiddleware
            end
          end
        end
      end
    end
  end
end
