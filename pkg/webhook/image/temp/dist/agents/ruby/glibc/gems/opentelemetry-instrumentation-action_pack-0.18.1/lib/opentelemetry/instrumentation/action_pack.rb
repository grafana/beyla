# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the ActionPack gem
    module ActionPack
    end
  end
end

require 'opentelemetry-instrumentation-rack'
require_relative 'action_pack/instrumentation'
require_relative 'action_pack/version'
