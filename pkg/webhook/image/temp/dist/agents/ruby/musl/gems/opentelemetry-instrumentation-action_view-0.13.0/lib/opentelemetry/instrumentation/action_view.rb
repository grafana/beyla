# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # (see OpenTelemetry::Instrumentation::ActionView::Instrumentation)
    module ActionView
    end
  end
end

require_relative 'action_view/instrumentation'
require_relative 'action_view/version'
