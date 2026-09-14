# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Lmdb gem
    module LMDB
    end
  end
end

require_relative 'lmdb/instrumentation'
require_relative 'lmdb/version'
