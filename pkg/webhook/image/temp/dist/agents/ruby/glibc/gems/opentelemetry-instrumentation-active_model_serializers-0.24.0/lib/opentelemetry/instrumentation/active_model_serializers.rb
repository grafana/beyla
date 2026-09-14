# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the ActiveModelSerializers gem
    module ActiveModelSerializers
    end
  end
end

require_relative 'active_model_serializers/instrumentation'
require_relative 'active_model_serializers/version'
