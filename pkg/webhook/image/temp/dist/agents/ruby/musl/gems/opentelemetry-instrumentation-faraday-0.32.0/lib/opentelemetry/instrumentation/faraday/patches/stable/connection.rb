# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Faraday
      module Patches
        module Stable
          # Module to be prepended to force Faraday to use the middleware by
          # default so the user doesn't have to call `use` for every connection.
          module Connection
            # Wraps Faraday::Connection#initialize:
            # https://github.com/lostisland/faraday/blob/ff9dc1d1219a1bbdba95a9a4cf5d135b97247ee2/lib/faraday/connection.rb#L62-L92
            def initialize(...)
              super.tap do
                use(:open_telemetry) unless builder.handlers.any? do |handler|
                  handler.klass == Middlewares::Stable::TracerMiddleware
                end
              end
            end
          end
        end
      end
    end
  end
end
