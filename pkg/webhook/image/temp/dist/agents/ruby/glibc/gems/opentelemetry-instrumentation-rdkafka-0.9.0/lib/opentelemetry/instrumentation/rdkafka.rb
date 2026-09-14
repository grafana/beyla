# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Rdkafka gem
    module Rdkafka
    end
  end
end

require_relative 'rdkafka/instrumentation'
require_relative 'rdkafka/version'
