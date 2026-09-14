# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Ethon gem
    module Ethon
    end
  end
end

require_relative 'ethon/http_helper'
require_relative 'ethon/instrumentation'
require_relative 'ethon/version'
