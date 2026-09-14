# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      # A View provides SDK users with the flexibility to customize the metrics that are output by the SDK.
      module View
      end
    end
  end
end

require 'opentelemetry/sdk/metrics/view/registered_view'
