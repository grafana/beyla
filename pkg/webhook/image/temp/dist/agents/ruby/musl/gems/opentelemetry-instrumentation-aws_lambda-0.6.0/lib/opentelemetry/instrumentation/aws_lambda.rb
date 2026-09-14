# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the aws_lambda gem
    module AwsLambda
    end
  end
end

require_relative 'aws_lambda/instrumentation'
require_relative 'aws_lambda/version'
