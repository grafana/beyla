# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry/common'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    module Net
      # Contains the OpenTelemetry instrumentation for the Net::HTTP gem
      module HTTP
      end
    end
  end
end

require_relative 'http/http_helper'
require_relative 'http/instrumentation'
require_relative 'http/version'
