# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Export
        # MetricReader provides a minimal example implementation.
        # It is not required to subclass this class to provide an implementation
        # of MetricReader, provided the interface is satisfied.
        class MetricReader
          attr_reader :metric_store

          def initialize
            @metric_store = OpenTelemetry::SDK::Metrics::State::MetricStore.new
          end

          def collect
            @metric_store.collect
          end

          def shutdown(timeout: nil)
            Export::SUCCESS
          end

          def force_flush(timeout: nil)
            Export::SUCCESS
          end
        end
      end
    end
  end
end
