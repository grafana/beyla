# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Rack
      # Provides utilities methods for creating Rack spans
      module Util
        require_relative 'util/queue_time'
      end
    end
  end
end
