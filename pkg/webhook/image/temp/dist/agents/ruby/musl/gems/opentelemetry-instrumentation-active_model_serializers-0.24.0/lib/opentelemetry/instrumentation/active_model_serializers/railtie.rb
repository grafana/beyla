# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveModelSerializers # :nodoc:
      def self.subscribe
        Instrumentation.instance.subscribe
      end

      if defined?(::Rails::Railtie)
        # This Railtie sets up subscriptions to relevant ActiveModelSerializers notifications
        class Railtie < ::Rails::Railtie
          config.after_initialize do
            ::OpenTelemetry::Instrumentation::ActiveModelSerializers.subscribe
          end
        end
      end
    end
  end
end
