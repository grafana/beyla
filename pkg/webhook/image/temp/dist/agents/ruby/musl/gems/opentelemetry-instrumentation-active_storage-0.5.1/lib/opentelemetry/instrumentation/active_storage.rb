# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the ActiveStorage gem
    module ActiveStorage
    end
  end
end

require_relative 'active_storage/instrumentation'
require_relative 'active_storage/version'
