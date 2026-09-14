# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveStorage
      SUBSCRIPTIONS = %w[
        preview.active_storage
        transform.active_storage
        analyze.active_storage
        service_upload.active_storage
        service_streaming_download.active_storage
        service_download_chunk.active_storage
        service_download.active_storage
        service_delete.active_storage
        service_delete_prefixed.active_storage
        service_exist.active_storage
        service_url.active_storage
        service_update_metadata.active_storage
      ].freeze

      # This Railtie sets up subscriptions to relevant ActiveStorage notifications
      class Railtie < ::Rails::Railtie
        config.after_initialize do
          ::OpenTelemetry::Instrumentation::ActiveSupport::Instrumentation.instance.install({})
          subscribe
        end

        class << self
          def subscribe
            SUBSCRIPTIONS.each do |subscription_name|
              ::OpenTelemetry::Instrumentation::ActiveSupport.subscribe(
                ActiveStorage::Instrumentation.instance.tracer,
                subscription_name,
                config[:notification_payload_transform],
                config[:disallowed_notification_payload_keys]
              )
            end
          end

          def unsubscribe
            SUBSCRIPTIONS.each do |subscription_name|
              ::ActiveSupport::Notifications.unsubscribe(subscription_name)
            end
          end

          def config
            ActiveStorage::Instrumentation.instance.config
          end
        end
      end
    end
  end
end
