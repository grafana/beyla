# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ConcurrentRuby
      # The Instrumentation class contains logic to detect and install the
      # ConcurrentRuby instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          require_dependencies
          patch
        end

        present do
          defined?(::Concurrent::ThreadPoolExecutor)
        end

        private

        def require_dependencies
          require_relative 'patches/thread_pool_executor'
        end

        def patch
          ::Concurrent::ThreadPoolExecutor.prepend Patches::ThreadPoolExecutor
        end
      end
    end
  end
end
