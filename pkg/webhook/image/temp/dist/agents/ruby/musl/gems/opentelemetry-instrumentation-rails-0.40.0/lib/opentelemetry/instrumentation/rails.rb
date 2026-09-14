# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Rails gem
    module Rails
    end
  end
end

require 'opentelemetry-instrumentation-action_pack'
require 'opentelemetry-instrumentation-active_support'
require 'opentelemetry-instrumentation-action_view'
require 'opentelemetry-instrumentation-action_mailer'
require 'opentelemetry-instrumentation-active_record'
require 'opentelemetry-instrumentation-active_storage'
require 'opentelemetry-instrumentation-active_job'
require 'opentelemetry-instrumentation-concurrent_ruby'
require_relative 'rails/instrumentation'
require_relative 'rails/version'
