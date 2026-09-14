# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'
require 'opentelemetry-helpers-sql'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Pg gem
    module PG
      extend ::OpenTelemetry::Helpers::Sql
    end
  end
end

require_relative 'pg/instrumentation'
require_relative 'pg/version'
