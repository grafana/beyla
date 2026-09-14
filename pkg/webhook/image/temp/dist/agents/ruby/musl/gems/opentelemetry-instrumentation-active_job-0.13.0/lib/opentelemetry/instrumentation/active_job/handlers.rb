# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative 'mappers/attribute'
require_relative 'handlers/default'
require_relative 'handlers/enqueue'
require_relative 'handlers/perform'
require_relative 'handlers/step'

module OpenTelemetry
  module Instrumentation
    module ActiveJob
      # Module that contains custom event handlers, which are used to generate spans per event
      module Handlers
        EVENT_NAMESPACE = 'active_job'

        module_function

        # Subscribes Event Handlers to relevant ActiveJob notifications
        #
        # The following events are recorded as spans:
        # - enqueue
        # - enqueue_at
        # - enqueue_retry
        # - perform
        # - retry_stopped
        # - discard
        # - step (Continuations, Rails 8.1+)
        #
        # Ingress and Egress spans (perform, enqueue, enqueue_at) use Messaging semantic conventions for naming the span,
        # while internal spans keep their ActiveSupport event name.
        #
        # @note this method is not thread safe and should not be used in a multi-threaded context
        # @note Why no perform_start?
        #       This event causes much heartache as it is the first in a series of events that is triggered.
        #       It should not be the ingress span because it does not measure anything.
        #       https://github.com/rails/rails/blob/v6.1.7.6/activejob/lib/active_job/instrumentation.rb#L14
        #       https://github.com/rails/rails/blob/v7.0.8/activejob/lib/active_job/instrumentation.rb#L19
        def subscribe
          return unless Array(@subscriptions).empty?

          mapper = Mappers::Attribute.new
          config = ActiveJob::Instrumentation.instance.config
          parent_span_provider = OpenTelemetry::Instrumentation::ActiveJob

          # TODO, use delegation instead of inheritance
          default_handler = Handlers::Default.new(parent_span_provider, mapper, config)
          enqueue_handler = Handlers::Enqueue.new(parent_span_provider, mapper, config)
          perform_handler = Handlers::Perform.new(parent_span_provider, mapper, config)
          step_handler = Handlers::Step.new(parent_span_provider, mapper, config)

          handlers_by_pattern = {
            'enqueue' => enqueue_handler,
            'enqueue_at' => enqueue_handler,
            'enqueue_retry' => default_handler,
            'perform' => perform_handler,
            'retry_stopped' => default_handler,
            'discard' => default_handler,
            'step' => step_handler
          }

          @subscriptions = handlers_by_pattern.map do |key, handler|
            ::ActiveSupport::Notifications.subscribe("#{key}.#{EVENT_NAMESPACE}", handler)
          end
        end

        # Removes Event Handler Subscriptions for ActiveJob notifications
        # @note this method is not thread-safe and should not be used in a multi-threaded context
        def unsubscribe
          @subscriptions&.each { |subscriber| ::ActiveSupport::Notifications.unsubscribe(subscriber) }
          @subscriptions = nil
        end
      end
    end
  end
end
