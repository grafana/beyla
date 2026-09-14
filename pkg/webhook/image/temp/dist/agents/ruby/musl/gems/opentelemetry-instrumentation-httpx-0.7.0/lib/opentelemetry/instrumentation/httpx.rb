# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Http gem
    module HTTPX
    end
  end
end

require_relative 'httpx/http_helper'
require_relative 'httpx/instrumentation'
require_relative 'httpx/version'
