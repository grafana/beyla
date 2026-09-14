# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      # The Aggregation module contains the OpenTelemetry metrics reference
      # aggregation implementations.
      module Aggregation
      end
    end
  end
end

require 'opentelemetry/sdk/metrics/aggregation/aggregation_temporality'
require 'opentelemetry/sdk/metrics/aggregation/number_data_point'
require 'opentelemetry/sdk/metrics/aggregation/histogram_data_point'
require 'opentelemetry/sdk/metrics/aggregation/explicit_bucket_histogram'
require 'opentelemetry/sdk/metrics/aggregation/sum'
require 'opentelemetry/sdk/metrics/aggregation/last_value'
require 'opentelemetry/sdk/metrics/aggregation/drop'
require 'opentelemetry/sdk/metrics/aggregation/exponential_histogram_data_point'
require 'opentelemetry/sdk/metrics/aggregation/exponential_bucket_histogram'
