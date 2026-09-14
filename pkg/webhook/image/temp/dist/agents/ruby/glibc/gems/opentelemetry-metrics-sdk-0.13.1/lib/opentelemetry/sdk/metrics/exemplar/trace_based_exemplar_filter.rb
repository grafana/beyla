# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Exemplar
        # TraceBasedExemplarFilter is an ExemplarFilter which makes measurements recorded
        # in the context of a sampled parent span eligible for being an Exemplar
        class TraceBasedExemplarFilter < ExemplarFilter
          def self.should_sample?(value, timestamp, attributes, context)
            current_span = ::OpenTelemetry::Trace.current_span(context)
            span_content = current_span.context
            trace_flags = span_content.trace_flags
            trace_flags.sampled?
          rescue StandardError => e
            OpenTelemetry.logger.error("Error in TraceBasedExemplarFilter: #{e.message}")
            false
          end
        end
      end
    end
  end
end
