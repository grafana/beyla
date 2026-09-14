# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module PG
      # The Instrumentation class contains logic to detect and install the Pg instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('1.1.0')

        install do |config|
          require_dependencies
          patch_client
          configure_propagator(config)
        end

        present do
          defined?(::PG)
        end

        compatible do
          gem_version > Gem::Version.new(MINIMUM_VERSION)
        end

        option :peer_service, default: nil, validate: :string
        option :db_statement, default: :obfuscate, validate: %I[omit include obfuscate]
        option :obfuscation_limit, default: 2000, validate: :integer
        option :propagator, default: 'none', validate: %w[none tracecontext]

        attr_reader :propagator

        private

        def gem_version
          Gem::Version.new(::PG::VERSION)
        end

        def require_dependencies
          require_relative 'patches/connection'
        end

        def patch_client
          ::PG::Connection.prepend(Patches::Connection)
          ::PG::Connection.singleton_class.prepend(Patches::Connect)
        end

        def configure_propagator(config)
          propagator = config[:propagator]
          @propagator = case propagator
                        when 'tracecontext' then OpenTelemetry::Helpers::SqlProcessor::SqlCommenter.sql_query_propagator
                        when 'none', nil then nil
                        else
                          OpenTelemetry.logger.warn "The #{propagator} propagator is unknown and cannot be configured"
                        end
        end
      end
    end
  end
end
