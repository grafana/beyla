# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/sdk'
require 'opentelemetry-metrics-api'

module OpenTelemetry
  module SDK
    # The Metrics module contains the OpenTelemetry metrics reference
    # implementation.
    module Metrics
    end
  end
end

require 'opentelemetry/sdk/metrics/version'
require 'opentelemetry/sdk/metrics/exemplar'
require 'opentelemetry/sdk/metrics/aggregation'
require 'opentelemetry/sdk/metrics/configurator_patch'
require 'opentelemetry/sdk/metrics/export'
require 'opentelemetry/sdk/metrics/fork_hooks'
require 'opentelemetry/sdk/metrics/instrument'
require 'opentelemetry/sdk/metrics/meter'
require 'opentelemetry/sdk/metrics/meter_provider'
require 'opentelemetry/sdk/metrics/state'
require 'opentelemetry/sdk/metrics/view'
