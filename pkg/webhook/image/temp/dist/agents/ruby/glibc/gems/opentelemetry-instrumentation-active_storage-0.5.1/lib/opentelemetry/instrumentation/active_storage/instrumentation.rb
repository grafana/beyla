# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveStorage
      # The {OpenTelemetry::Instrumentation::ActiveStorage::Instrumentation} class contains logic to detect and install the ActiveStorage instrumentation
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
      # - `array` **default** `[]`
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
      # ### `:key`
      #
      # - `symbol` **default** `:omit`
      #
      # Specifies whether to include secure token in the notification payload. Valid values are `:omit` and `:include`.
      #
      # ### `:url`
      #
      # - `symbol` **default** `:omit`
      #
      # Specifies whether to include url in the notification payload. Valid values are `:omit` and `:include`.
      #
      # @example An explicit default configuration
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use_all({
      #       'OpenTelemetry::Instrumentation::ActionMailer' => {
      #         disallowed_notification_payload_keys: [],
      #         notification_payload_transform: nil,
      #         key: :omit,
      #         url: :omit,
      #       },
      #     })
      #   end
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('7.1')

        install do |_config|
          resolve_key
          resolve_url
          resolve_payload_transform
          require_dependencies
        end

        present do
          defined?(::ActiveStorage)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        option :disallowed_notification_payload_keys, default: [],  validate: :array
        option :notification_payload_transform,       default: nil, validate: :callable
        option :key,                                  default: :omit, validate: %I[omit include]
        option :url,                                  default: :omit, validate: %I[omit include]

        private

        def gem_version
          ::ActiveStorage.version
        end

        def resolve_key
          return unless _config[:key] == :omit

          _config[:disallowed_notification_payload_keys].append 'active_storage.key'
        end

        def resolve_url
          return unless _config[:url] == :omit

          _config[:disallowed_notification_payload_keys].append 'active_storage.url'
        end

        def resolve_payload_transform
          if _config[:notification_payload_transform].nil?
            transform_attributes = ->(payload) { transform_payload(payload) }
          else
            original_callable = _config[:notification_payload_transform]
            transform_attributes = lambda do |payload|
              new_payload = transform_payload(payload)
              user_payload = original_callable.call(new_payload)
              if user_payload.instance_of?(Hash)
                user_payload
              else
                OpenTelemetry.logger.error("ActiveStorage: transformed payload is #{user_payload.class} (require Hash)")
                new_payload
              end
            end
          end
          _config[:notification_payload_transform] = transform_attributes
        end

        def _config
          ActiveStorage::Instrumentation.instance.config
        end

        # add `active_storage.` prefix to each attribute
        def transform_payload(payload)
          payload.transform_keys { |k| "active_storage.#{k}" }
        end

        def require_dependencies
          require_relative 'railtie'
        end
      end
    end
  end
end
