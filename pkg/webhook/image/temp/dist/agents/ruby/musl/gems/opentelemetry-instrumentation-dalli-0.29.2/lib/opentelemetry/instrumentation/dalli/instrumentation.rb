# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Dalli
      # The Instrumentation class contains logic to detect and install the Dalli
      # instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MAX_VERSION = Gem::Version.new('4.1.0') # Dalli 4.2.0+ has native OpenTelemetry instrumentation

        install do |_config|
          require_dependencies
          add_patches
        end

        present do
          defined?(::Dalli)
        end

        compatible do
          if gem_version > MAX_VERSION
            OpenTelemetry.logger.info("Dalli #{gem_version} has native OpenTelemetry support. Skipping community instrumentation.")
            false
          else
            true
          end
        end

        option :peer_service, default: nil, validate: :string
        option :db_statement, default: :obfuscate, validate: %I[omit obfuscate include]

        private

        def gem_version
          Gem::Version.new(::Dalli::VERSION)
        end

        def require_dependencies
          require_relative 'utils'
          require_relative 'patches/server'
        end

        def add_patches
          if gem_version < Gem::Version.new('3.0.0')
            ::Dalli::Server.prepend(Patches::Server)
          else
            ::Dalli::Protocol::Binary.prepend(Patches::Server) if defined?(::Dalli::Protocol::Binary)
            ::Dalli::Protocol::Meta.prepend(Patches::Server) if defined?(::Dalli::Protocol::Meta)
          end
        end
      end
    end
  end
end
