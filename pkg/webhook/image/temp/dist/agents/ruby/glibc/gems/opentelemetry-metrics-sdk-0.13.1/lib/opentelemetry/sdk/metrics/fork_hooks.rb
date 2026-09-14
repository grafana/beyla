# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      # ForkHooks implements methods to run callbacks before and after forking a Process by overriding Process::_fork
      # This is used to ensure that the PeriodicMetricReader is restarted after forking
      module ForkHooks
        def self.attach!
          return if @fork_hooks_attached

          Process.singleton_class.prepend(ForkHooks)
          @fork_hooks_attached = true
        end

        def self.after_fork
          ::OpenTelemetry.meter_provider.metric_readers.each do |reader|
            reader.after_fork if reader.respond_to?(:after_fork)
          end
        end

        def _fork
          parent_pid = Process.pid
          super.tap do
            ForkHooks.after_fork unless Process.pid == parent_pid
          end
        end
      end
    end
  end
end
