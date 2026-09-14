# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/metrics/instrument/counter'
require 'opentelemetry/metrics/instrument/histogram'
require 'opentelemetry/metrics/instrument/gauge'
require 'opentelemetry/metrics/instrument/observable_counter'
require 'opentelemetry/metrics/instrument/observable_gauge'
require 'opentelemetry/metrics/instrument/observable_up_down_counter'
require 'opentelemetry/metrics/instrument/up_down_counter'

module OpenTelemetry
  module Metrics
    # Instruments are used to report Measurements.
    module Instrument
    end
  end
end
