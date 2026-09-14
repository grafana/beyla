# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module LMDB
      # The Instrumentation class contains logic to detect and install the LMDB instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          require_dependencies
          patch
        end

        present do
          defined?(::LMDB)
        end

        option :peer_service, default: nil, validate: :string
        option :db_statement, default: :include, validate: %I[omit include]

        private

        def patch
          ::LMDB::Environment.prepend(Patches::Environment)
          ::LMDB::Database.prepend(Patches::Database)
        end

        def require_dependencies
          require_relative 'patches/database'
          require_relative 'patches/environment'
        end
      end
    end
  end
end
