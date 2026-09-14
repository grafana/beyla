# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # (see OpenTelemetry::Instrumentation::Resque::Instrumentation)
    module Resque
    end
  end
end

require_relative 'resque/instrumentation'
require_relative 'resque/version'
