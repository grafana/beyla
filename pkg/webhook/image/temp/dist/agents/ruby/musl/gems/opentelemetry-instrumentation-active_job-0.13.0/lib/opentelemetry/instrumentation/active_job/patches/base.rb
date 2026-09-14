# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveJob
      module Patches
        # Module to prepend to ActiveJob::Core for context propagation.
        module Base
          def self.prepended(base)
            base.class_eval do
              attr_accessor :__otel_headers
            end
          end

          def initialize(...)
            @__otel_headers = {}
            super
          end

          def serialize
            message = super

            begin
              message.merge!('__otel_headers' => serialize_arguments(@__otel_headers))
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e)
            end

            message
          end

          def deserialize(job_data)
            begin
              @__otel_headers = deserialize_arguments(job_data.delete('__otel_headers') || []).to_h
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e)
            end
            super
          end
        end
      end
    end
  end
end
