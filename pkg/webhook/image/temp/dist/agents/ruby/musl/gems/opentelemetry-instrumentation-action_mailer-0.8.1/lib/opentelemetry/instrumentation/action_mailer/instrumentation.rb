# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActionMailer
      # The {OpenTelemetry::Instrumentation::ActionMailer::Instrumentation} class contains logic to detect and install the ActionMailer instrumentation
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
      # Specifies an array of keys that should be excluded from the `deliver.action_mailer` notification payload as span attributes.
      #
      # ### `:disallowed_process_payload_keys`
      #
      # Specifies an array of keys that should be excluded from the `process.action_mailer` notification payload as span attributes.
      #
      # ### `:notification_payload_transform`
      #
      # - `proc` **default** `nil`
      #
      # Specifies custom proc used to extract span attributes form the `deliver.action_mailer` notification payload. Use this to rename keys, extract nested values, or perform any other custom logic.
      #
      # ### `:process_payload_transform`
      #
      # - `proc` **default** `nil`
      #
      # Specifies custom proc used to extract span attributes form the `process.action_mailer` notification payload. Use this to rename keys, extract nested values, or perform any other custom logic.
      #
      # ### `:email_address`
      #
      # - `symbol` **default** `:omit`
      #
      # Specifies whether to include email addresses in the notification payload. Valid values are `:omit` and `:include`.
      #
      # @example An explicit default configuration
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use_all({
      #       'OpenTelemetry::Instrumentation::ActionMailer' => {
      #         disallowed_notification_payload_keys: [],
      #         disallowed_process_payload_keys: [],
      #         notification_payload_transform: nil,
      #         process_payload_transform: nil,
      #         email_address: :omit,
      #       },
      #     })
      #   end
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('7.1')
        EMAIL_ATTRIBUTE = %w[email.to.address email.from.address email.cc.address email.bcc.address].freeze

        install do |_config|
          resolve_email_address
          ecs_mail_convention
          require_dependencies
        end

        present do
          defined?(::ActionMailer)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        option :disallowed_notification_payload_keys, default: [], validate: :array
        option :disallowed_process_payload_keys,      default: [], validate: :array
        option :notification_payload_transform,       default: nil, validate: :callable
        option :process_payload_transform,            default: nil, validate: :callable
        option :email_address,                        default: :omit, validate: %I[omit include]

        private

        def gem_version
          ::ActionMailer.version
        end

        def resolve_email_address
          return unless _config[:email_address] == :omit

          _config[:disallowed_notification_payload_keys] += EMAIL_ATTRIBUTE
        end

        def ecs_mail_convention
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
                OpenTelemetry.logger.error("ActionMailer: transformed payload is #{user_payload.class} (require Hash)")
                new_payload
              end
            end
          end
          _config[:notification_payload_transform] = transform_attributes
        end

        def _config
          ActionMailer::Instrumentation.instance.config
        end

        # email attribute key convention is obtained from: https://www.elastic.co/guide/en/ecs/8.11/ecs-email.html
        def transform_payload(payload)
          new_payload = {}
          new_payload['email.message_id'] = payload[:message_id] if payload[:message_id]
          new_payload['email.subject'] = payload[:subject] if payload[:subject]
          new_payload['email.x_mailer'] = payload[:mailer] if payload[:mailer]
          new_payload['email.to.address'] = payload[:to] if payload[:to]
          new_payload['email.from.address'] = payload[:from] if payload[:from]
          new_payload['email.cc.address'] = payload[:cc] if payload[:cc]
          new_payload['email.bcc.address'] = payload[:bcc] if payload[:bcc]
          new_payload['email.origination_timestamp'] = payload[:date] if payload[:date]
          new_payload
        end

        def require_dependencies
          require_relative 'railtie'
        end
      end
    end
  end
end
