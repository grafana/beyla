# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Grape
      # The Instrumentation class contains logic to detect and install the Grape instrumentation
      # # Configuration keys and options
      # ## `:ignored_events`
      #
      # Default is `[]`. Specifies which ActiveSupport::Notifications events published by Grape to ignore.
      # Ignored events will not be published as Span events.
      #
      # ## `:install_rack`
      #
      # Default is `true`. Specifies whether or not to install the Rack instrumentation as part of installing the Grape instrumentation.
      # This is useful in cases where you have multiple Rack applications but want to manually specify where to insert the tracing middleware.
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        # Minimum Grape version needed for compatibility with this instrumentation
        MINIMUM_VERSION = Gem::Version.new('1.2.0')

        install do |_config|
          install_rack_instrumentation
          require_dependencies
          subscribe
        end

        present do
          defined?(::Grape)
        end

        compatible do
          !defined?(::ActiveSupport::Notifications).nil? && gem_version >= MINIMUM_VERSION
        end

        option :ignored_events, default: [], validate: :array
        option :install_rack, default: true, validate: :boolean

        private

        def gem_version
          Gem::Version.new(::Grape::VERSION)
        end

        def install_rack_instrumentation
          return unless config[:install_rack]

          OpenTelemetry::Instrumentation::Rack::Instrumentation.instance.install({})
        end

        def require_dependencies
          require_relative 'subscriber'
        end

        def subscribe
          Subscriber.subscribe
        end
      end
    end
  end
end
