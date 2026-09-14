# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module HTTPX
      # Base Plugin
      module Plugin
        # Request patch to initiate the trace on initialization.
        module RequestMethods
          attr_accessor :init_time

          # intercepts request initialization to inject the tracing logic.
          def initialize(*)
            super

            @init_time = nil

            RequestTracer.call(self)
          end

          def response=(*)
            # init_time should be set when it's send to a connection.
            # However, there are situations where connection initialization fails.
            # Example is the :ssrf_filter plugin, which raises an error on
            # initialize if the host is an IP which matches against the known set.
            # in such cases, we'll just set here right here.
            @init_time ||= ::Time.now

            super
          end
        end

        # Connection mixin
        module ConnectionMethods
          def initialize(*)
            super

            @init_time = ::Time.now
          end

          def send(request)
            request.init_time ||= @init_time

            super
          end
        end
      end
    end
  end
end
