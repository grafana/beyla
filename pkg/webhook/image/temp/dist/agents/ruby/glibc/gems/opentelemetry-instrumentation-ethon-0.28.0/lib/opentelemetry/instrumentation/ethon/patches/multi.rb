# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Ethon
      module Patches
        # Ethon::Multi patch for instrumentation
        module Multi
          def perform
            easy_handles.each do |easy|
              easy.otel_before_request unless easy.otel_span_started?
            end

            super
          end

          def add(easy)
            easy.otel_before_request unless easy.otel_span_started?

            super
          end
        end
      end
    end
  end
end
