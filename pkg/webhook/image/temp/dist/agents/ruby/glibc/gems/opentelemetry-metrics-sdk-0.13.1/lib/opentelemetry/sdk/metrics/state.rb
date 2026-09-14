# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      # @api private
      #
      # The State module provides SDK internal functionality that is not a part of the
      # public API.
      module State
      end
    end
  end
end

require 'opentelemetry/sdk/metrics/state/metric_data'
require 'opentelemetry/sdk/metrics/state/metric_store'
require 'opentelemetry/sdk/metrics/state/metric_stream'
require 'opentelemetry/sdk/metrics/state/asynchronous_metric_stream'
