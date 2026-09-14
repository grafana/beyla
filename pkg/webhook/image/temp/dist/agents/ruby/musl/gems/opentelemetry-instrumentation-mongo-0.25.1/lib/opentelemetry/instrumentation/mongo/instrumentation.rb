# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Mongo
      # Instrumentation class that detects and installs the Mongo instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('2.5.0')
        MAX_VERSION = Gem::Version.new('2.22.0') # Mongo 2.23.0+ has native OpenTelemetry instrumentation

        install do |_config|
          require_dependencies
          register_subscriber
        end

        present do
          !defined?(::Mongo::Monitoring::Global).nil?
        end

        compatible do
          if gem_version < MINIMUM_VERSION
            false
          elsif gem_version > MAX_VERSION
            OpenTelemetry.logger.info("Mongo #{gem_version} has native OpenTelemetry support. Skipping community instrumentation.")
            false
          else
            true
          end
        end

        option :peer_service, default: nil, validate: :string
        option :db_statement, default: :obfuscate, validate: %I[omit obfuscate include]

        private

        def gem_version
          Gem::Version.new(::Mongo::VERSION)
        end

        def require_dependencies
          require_relative 'subscriber'
        end

        def register_subscriber
          # Subscribe to all COMMAND queries with our subscriber class
          ::Mongo::Monitoring::Global.subscribe(::Mongo::Monitoring::COMMAND, Subscriber.new)
        end
      end
    end
  end
end
