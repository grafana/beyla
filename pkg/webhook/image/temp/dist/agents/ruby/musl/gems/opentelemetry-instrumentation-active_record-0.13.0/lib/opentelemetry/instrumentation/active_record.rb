# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the ActiveRecord gem
    module ActiveRecord
    end
  end
end

require_relative 'active_record/instrumentation'
require_relative 'active_record/version'
