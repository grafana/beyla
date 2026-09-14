# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Anthropic gem
    module Anthropic
    end
  end
end

require_relative 'anthropic/instrumentation'
require_relative 'anthropic/version'
