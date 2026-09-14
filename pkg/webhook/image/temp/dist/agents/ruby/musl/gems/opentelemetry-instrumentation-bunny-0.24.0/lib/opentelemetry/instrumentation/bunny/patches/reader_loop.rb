# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Bunny
      module Patches
        # The ReaderLoop module contains the instrumentation patch the ReaderLoop#run_once method
        module ReaderLoop
          def run_once
            attributes = OpenTelemetry::Instrumentation::Bunny::PatchHelpers.basic_attributes(nil, @transport, '', nil)
            tracer.in_span('Bunny::ReaderLoop#run_once', attributes: attributes, kind: :consumer) do
              super
            end
          end

          private

          def tracer
            Bunny::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
