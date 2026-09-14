# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Grpc
      module Patches
        # Module to be prepended to force gRPC to use the client interceptor by
        # default so the user doesn't have to manually add it when initializing a client.
        module ClientStub
          def initialize(host, creds, **args)
            interceptors = args[:interceptors] || []
            interceptors.unshift(Interceptors::ClientTracer.new) unless interceptors.any?(Interceptors::ClientTracer)
            args[:interceptors] = interceptors

            super
          end
        end
      end
    end
  end
end
