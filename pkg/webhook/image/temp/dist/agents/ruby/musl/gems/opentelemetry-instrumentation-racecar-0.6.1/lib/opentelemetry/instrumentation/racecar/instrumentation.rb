# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Racecar
      # The Instrumentation class contains logic to detect and install the Racecar instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('2.7')

        compatible do
          !defined?(::ActiveSupport::Notifications).nil? && gem_version >= MINIMUM_VERSION
        end

        install do |_config|
          require_patches
          patch
          add_subscribers
        end

        present do
          defined?(::Racecar)
        end

        private

        def require_patches
          require_relative 'patches/consumer'
        end

        def add_subscribers
          require_relative 'process_message_subscriber'
          subscriber = ProcessMessageSubscriber.new
          ::ActiveSupport::Notifications.subscribe('process_message.racecar', subscriber)
        end

        def patch
          ::Racecar::Consumer.prepend(Patches::Consumer)
        end

        def gem_version
          require 'racecar/version'
          Gem::Version.new(::Racecar::VERSION)
        end
      end
    end
  end
end
