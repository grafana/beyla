# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the ConcurrentRuby gem
    module ConcurrentRuby
    end
  end
end

require_relative 'concurrent_ruby/instrumentation'
require_relative 'concurrent_ruby/version'
