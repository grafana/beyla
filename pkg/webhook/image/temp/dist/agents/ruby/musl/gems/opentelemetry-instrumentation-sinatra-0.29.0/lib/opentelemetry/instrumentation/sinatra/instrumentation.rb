# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative 'extensions/tracer_extension'

module OpenTelemetry
  module Instrumentation
    module Sinatra
      # The {OpenTelemetry::Instrumentation::Sinatra::Instrumentation} class contains logic to detect and install the Sinatra instrumentation
      #
      # Installation and configuration of this instrumentation is done within the
      # {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry/SDK#configure-instance_method OpenTelemetry::SDK#configure}
      # block, calling {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use use()}
      # or {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use_all use_all()}.
      #
      # ## Configuration keys and options
      #
      # ### `:install_rack`
      #
      # Default is `true`. Specifies whether or not to install the Rack instrumentation as part of installing the Sinatra instrumentation.
      # This is useful in cases where you have multiple Rack applications but want to manually specify where to insert the tracing middleware.
      #
      # @example Manually install Rack instrumentation.
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use_all({
      #       'OpenTelemetry::Instrumentation::Rack' => { },
      #       'OpenTelemetry::Instrumentation::Sinatra' => {
      #         install_rack: false
      #       },
      #     })
      #   end
      #
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |config|
          OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.install({}) if config[:install_rack]

          unless OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.installed?
            OpenTelemetry.logger.warn('Rack instrumentation is required for Sinatra but not installed. Please see the docs for more details: https://opentelemetry.io/docs/languages/ruby/libraries/')
          end

          ::Sinatra::Base.register Extensions::TracerExtension
        end

        option :install_rack, default: true, validate: :boolean

        present do
          defined?(::Sinatra)
        end

        def install_middleware(app)
          app.use(*OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.middleware_args) if config[:install_rack]
          app.use(Middlewares::TracerMiddleware)
        end
      end
    end
  end
end
