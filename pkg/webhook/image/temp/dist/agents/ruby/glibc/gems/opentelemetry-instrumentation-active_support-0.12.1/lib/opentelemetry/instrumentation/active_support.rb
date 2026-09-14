# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the ActiveSupport gem
    module ActiveSupport
    end
  end
end

require_relative 'active_support/instrumentation'
require_relative 'active_support/version'
