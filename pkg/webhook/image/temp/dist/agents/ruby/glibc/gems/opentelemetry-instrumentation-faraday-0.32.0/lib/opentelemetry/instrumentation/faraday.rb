# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry/common'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Faraday gem
    module Faraday
    end
  end
end

require_relative 'faraday/http_helper'
require_relative 'faraday/instrumentation'
require_relative 'faraday/version'
