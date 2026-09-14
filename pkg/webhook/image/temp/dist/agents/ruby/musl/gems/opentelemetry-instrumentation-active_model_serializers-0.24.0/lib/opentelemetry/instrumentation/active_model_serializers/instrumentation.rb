# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry-instrumentation-active_support'

module OpenTelemetry
  module Instrumentation
    module ActiveModelSerializers
      # Instrumentation class that detects and installs the ActiveModelSerializers instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        # Minimum supported version of the `active_model_serializers` gem
        MINIMUM_VERSION = Gem::Version.new('0.10.0')

        # ActiveSupport::Notification topics to which the instrumentation subscribes
        SUBSCRIPTIONS = %w[
          render.active_model_serializers
        ].freeze

        install do |_config|
          install_active_support_instrumenation
          require_dependencies
        end

        present do
          !defined?(::ActiveModelSerializers).nil?
        end

        compatible do
          !defined?(::ActiveSupport::Notifications).nil? && gem_version >= MINIMUM_VERSION
        end

        def subscribe
          SUBSCRIPTIONS.each do |subscription_name|
            OpenTelemetry.logger.debug("Subscribing to #{subscription_name} notifications with #{_tracer}")
            OpenTelemetry::Instrumentation::ActiveSupport.subscribe(_tracer, subscription_name, default_attribute_transformer)
          end
        end

        private

        def _tracer
          self.class.instance.tracer
        end

        def gem_version
          Gem::Version.new(::ActiveModel::Serializer::VERSION)
        end

        def install_active_support_instrumenation
          OpenTelemetry::Instrumentation::ActiveSupport::Instrumentation.instance.install({})
        end

        def require_dependencies
          require_relative 'railtie'
        end

        def default_attribute_transformer
          lambda { |payload|
            {
              'serializer.name' => payload[:serializer].name,
              'serializer.renderer' => 'active_model_serializers',
              'serializer.format' => payload[:adapter]&.class&.name || 'default'
            }
          }
        end
      end
    end
  end
end
