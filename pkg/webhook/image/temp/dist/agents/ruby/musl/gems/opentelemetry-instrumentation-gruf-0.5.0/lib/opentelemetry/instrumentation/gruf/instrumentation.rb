# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Gruf
      # The Instrumentation class contains logic to detect and install the Gruf instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          require_dependencies
        end

        option :peer_service, default: nil, validate: :string
        option :grpc_ignore_methods_on_client, default: [], validate: :array
        option :grpc_ignore_methods_on_server, default: [], validate: :array
        option :allowed_metadata_headers, default: [], validate: :array

        present do
          defined?(::Gruf)
        end

        private

        def require_dependencies
          require_relative 'interceptors/client'
          require_relative 'interceptors/server'
        end
      end
    end
  end
end
