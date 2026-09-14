# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Ruby-Kafka gem
    module RubyKafka
    end
  end
end

require_relative 'ruby_kafka/instrumentation'
require_relative 'ruby_kafka/version'
