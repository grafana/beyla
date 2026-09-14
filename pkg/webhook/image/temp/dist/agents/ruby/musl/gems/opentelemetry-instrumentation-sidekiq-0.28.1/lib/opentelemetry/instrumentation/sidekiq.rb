# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # (see {OpenTelemetry::Instrumentation::Sidekiq::Instrumentation})
    module Sidekiq
    end
  end
end

require_relative 'sidekiq/instrumentation'
require_relative 'sidekiq/version'
require 'opentelemetry/common'
