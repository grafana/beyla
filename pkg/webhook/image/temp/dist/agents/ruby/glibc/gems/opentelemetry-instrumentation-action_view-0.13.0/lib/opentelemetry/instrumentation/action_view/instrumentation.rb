# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActionView
      # The {OpenTelemetry::Instrumentation::ActionView::Instrumentation} class contains logic to detect and install the ActionView instrumentation
      #
      # Installation and configuration of this instrumentation is done within the
      # {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry/SDK#configure-instance_method OpenTelemetry::SDK#configure}
      # block, calling {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use use()}
      # or {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use_all use_all()}.
      #
      # ## Configuration keys and options
      #
      # ### `:disallowed_notification_payload_keys`
      #
      # Specifies an array of keys that should be excluded from the notification payload as span attributes.
      #
      # ### `:notification_payload_transform`
      #
      # - `proc` **default** `nil`
      #
      # Specifies custom proc used to extract span attributes form the notification payload.
      # Use this to rename keys, extract nested values, or perform any other custom logic.
      #
      # ### `:legacy_span_names`
      #
      # - `boolean`  **default** `false`
      #
      # Specifies whether spans names should use the legacy format where the subscription was reverse ordered and white space separated. (Ex. `action_view render_template`)
      # If set to `true`, the span name will match the name of the notification itself. (Ex. `render_template.action_view`)
      #
      # @example An explicit default configuration
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use_all({
      #       'OpenTelemetry::Instrumentation::ActionView' => {
      #         disallowed_notification_payload_keys: [],
      #         legacy_span_names: true,
      #       },
      #     })
      #   end
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('7.1')
        install do |_config|
          require_dependencies
        end

        present do
          defined?(::ActionView)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        option :disallowed_notification_payload_keys, default: [],  validate: :array
        option :notification_payload_transform,       default: nil, validate: :callable
        option :legacy_span_names,                    default: false, validate: :boolean

        private

        def gem_version
          ::ActionView.version
        end

        def require_dependencies
          require_relative 'railtie'
        end
      end
    end
  end
end
