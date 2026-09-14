# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  # The Logs API records a timestamped record with metadata.
  # In OpenTelemetry, any data that is not part of a distributed trace or a
  # metric is a log. For example, events are a specific type of log.
  #
  # This API is provided for logging library authors to build log
  # appenders/bridges. It should NOT be used directly by application
  # developers.
  module Logs
  end
end

require 'opentelemetry/logs/log_record'
require 'opentelemetry/logs/logger'
require 'opentelemetry/logs/logger_provider'
require 'opentelemetry/logs/severity_number'
