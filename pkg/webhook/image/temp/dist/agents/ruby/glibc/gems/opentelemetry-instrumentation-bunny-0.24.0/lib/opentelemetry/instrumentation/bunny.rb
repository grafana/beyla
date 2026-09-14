# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the bunny gem
    module Bunny
    end
  end
end

require_relative 'bunny/instrumentation'
require_relative 'bunny/version'
