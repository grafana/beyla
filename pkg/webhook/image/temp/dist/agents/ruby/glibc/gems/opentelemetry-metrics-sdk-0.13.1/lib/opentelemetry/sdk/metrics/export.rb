# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Export
        ExportError = Class.new(OpenTelemetry::Error)

        # The operation finished successfully.
        SUCCESS = 0

        # The operation finished with an error.
        FAILURE = 1

        # The operation timed out.
        TIMEOUT = 2
      end
    end
  end
end

require 'opentelemetry/sdk/metrics/export/metric_reader'
require 'opentelemetry/sdk/metrics/export/in_memory_metric_pull_exporter'
require 'opentelemetry/sdk/metrics/export/console_metric_pull_exporter'
require 'opentelemetry/sdk/metrics/export/periodic_metric_reader'
