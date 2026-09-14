# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # (see OpenTelemetry::Instrumentation::Sinatra::Instrumentation)
    module Sinatra
    end
  end
end

require_relative 'sinatra/instrumentation'
require_relative 'sinatra/version'
