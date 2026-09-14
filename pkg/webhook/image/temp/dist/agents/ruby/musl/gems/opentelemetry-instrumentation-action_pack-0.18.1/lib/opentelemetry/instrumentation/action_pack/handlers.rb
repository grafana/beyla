# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative 'handlers/action_controller'

module OpenTelemetry
  module Instrumentation
    module ActionPack
      # Module that contains custom event handlers, which are used to generate spans per event
      module Handlers
        module_function

        def subscribe
          return unless Array(@subscriptions).empty?

          config = ActionPack::Instrumentation.instance.config
          handlers_by_pattern = {
            'process_action.action_controller' => Handlers::ActionController.new(config)
          }

          @subscriptions = handlers_by_pattern.map do |key, handler|
            ::ActiveSupport::Notifications.subscribe(key, handler)
          end
        end

        # Removes Event Handler Subscriptions for Action Controller notifications
        # @note this method is not thread-safe and should not be used in a multi-threaded context
        def unsubscribe
          @subscriptions&.each { |subscriber| ::ActiveSupport::Notifications.unsubscribe(subscriber) }
          @subscriptions = nil
        end
      end
    end
  end
end
