# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the GraphQL gem
    module GraphQL
    end
  end
end

require_relative 'graphql/instrumentation'
require_relative 'graphql/version'
