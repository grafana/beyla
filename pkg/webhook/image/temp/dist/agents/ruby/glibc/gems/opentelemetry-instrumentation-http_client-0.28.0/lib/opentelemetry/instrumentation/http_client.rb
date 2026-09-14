# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the HttpClient gem
    module HttpClient
    end
  end
end

require_relative 'http_client/http_helper'
require_relative 'http_client/instrumentation'
require_relative 'http_client/version'
