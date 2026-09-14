# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Aws gem
    module AwsSdk
    end
  end
end

require_relative 'aws_sdk/instrumentation'
require_relative 'aws_sdk/version'
