# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'
require 'opentelemetry-helpers-sql'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Trilogy gem
    module Trilogy
      extend ::OpenTelemetry::Helpers::Sql
    end
  end
end

require_relative 'trilogy/instrumentation'
require_relative 'trilogy/version'
