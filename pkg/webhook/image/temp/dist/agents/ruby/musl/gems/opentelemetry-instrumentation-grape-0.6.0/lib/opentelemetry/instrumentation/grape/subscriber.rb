# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative 'event_handler'

module OpenTelemetry
  module Instrumentation
    module Grape
      # Manages all subscriptions, both for custom subscribers and built-in notifications
      class Subscriber
        class << self
          # Subscribe to all notifications (except those specified in the :ignored_events configs)
          def subscribe
            subscriptions = filter_ignored_events(SUBSCRIPTIONS)
            subscriptions.each do |subscriber_method, event|
              ::ActiveSupport::Notifications.subscribe(event) do |*args|
                EventHandler.send(subscriber_method, *args)
              end
            end
          end

          # ActiveSupport::Notifications that can be subscribed to using the documented `.subscribe` interface.
          # Reference: https://api.rubyonrails.org/classes/ActiveSupport/Notifications.html#method-c-subscribe
          SUBSCRIPTIONS = {
            endpoint_run: 'endpoint_run.grape',
            endpoint_render: 'endpoint_render.grape',
            endpoint_run_filters: 'endpoint_run_filters.grape',
            format_response: 'format_response.grape'
          }.freeze

          private_constant :SUBSCRIPTIONS

          private

          def filter_ignored_events(subscriptions)
            # Do not ignore 'endpoint_run' event
            ignored_events = config[:ignored_events] - [:endpoint_run]
            subscriptions.reject { |event| ignored_events.include?(event) }
          end

          def config
            Grape::Instrumentation.instance.config
          end
        end
      end
    end
  end
end
