# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActionPack
      # This Railtie installs Rack middleware to support Action Pack instrumentation
      class Railtie < ::Rails::Railtie
        config.before_initialize do |app|
          OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.install({})
          app.middleware.insert_before(
            0,
            *OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.middleware_args
          )
        end
      end
    end
  end
end
