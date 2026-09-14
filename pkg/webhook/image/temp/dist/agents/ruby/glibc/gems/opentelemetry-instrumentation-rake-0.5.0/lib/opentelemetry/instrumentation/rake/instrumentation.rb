# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Rake
      # The Instrumentation class contains logic to detect and install the Rake instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('0.9.0')

        install do |_config|
          require_dependencies
          patch_rake
        end

        present do
          defined?(::Rake::Task)
        end

        compatible do
          gem_version >= MINIMUM_VERSION
        end

        private

        def gem_version
          Gem::Version.new(::Rake::VERSION)
        end

        def require_dependencies
          require_relative 'patches/task'
        end

        def patch_rake
          ::Rake::Task.prepend(Patches::Task)
        end
      end
    end
  end
end
