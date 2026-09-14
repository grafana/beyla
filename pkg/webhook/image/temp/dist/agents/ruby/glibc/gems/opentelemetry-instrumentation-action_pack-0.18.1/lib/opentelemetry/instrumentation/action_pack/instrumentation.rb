# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActionPack
      # The {OpenTelemetry::Instrumentation::ActionPack::Instrumentation} class contains logic to detect and install the ActionPack instrumentation
      #
      # Installation and configuration of this instrumentation is done within the
      # {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry/SDK#configure-instance_method OpenTelemetry::SDK#configure}
      # block, calling {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use use()}
      # or {https://www.rubydoc.info/gems/opentelemetry-sdk/OpenTelemetry%2FSDK%2FConfigurator:use_all use_all()}.
      #
      # ## Configuration keys and options
      #
      # ### `:span_naming`
      #
      # Specifies how the span names are set. Can be one of:
      #
      # - `:semconv` **(default)** - The span name will use HTTP semantic conventions '{method http.route}', for example `GET /users/:id`
      # - `:class` - The span name will appear as '<ActionController class name>#<action>',
      #   for example `UsersController#show`.
      #
      # @example An explicit default configuration
      #   OpenTelemetry::SDK.configure do |c|
      #     c.use_all({
      #       'OpenTelemetry::Instrumentation::ActionPack' => {
      #         span_naming: :class
      #       },
      #     })
      #   end
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('7.1')

        install do |_config|
          require_railtie
          require_dependencies
          patch
        end

        option :span_naming, default: :semconv, validate: %i[semconv class]

        present do
          defined?(::ActionController)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        private

        def gem_version
          ::ActionPack.version
        end

        def patch
          Handlers.subscribe
        end

        def require_dependencies
          require_relative 'handlers'
        end

        def require_railtie
          require_relative 'railtie'
        end
      end
    end
  end
end
