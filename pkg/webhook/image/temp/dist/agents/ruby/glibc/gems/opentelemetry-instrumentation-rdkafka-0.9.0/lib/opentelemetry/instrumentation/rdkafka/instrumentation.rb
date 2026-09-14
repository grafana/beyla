# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Rdkafka
      # The Instrumentation class contains logic to detect and install the Rdkafka instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        compatible do
          gem_version = Gem::Version.new(::Rdkafka::VERSION)
          Gem::Requirement.new('>= 0.18.0').satisfied_by?(gem_version)
        end

        install do |_config|
          require_patches
          patch
        end

        present do
          defined?(::Rdkafka)
        end

        private

        def require_patches
          require_relative 'patches/producer'
          require_relative 'patches/consumer'
        end

        def patch
          ::Rdkafka::Producer.prepend(Patches::Producer)
          ::Rdkafka::Consumer.prepend(Patches::Consumer)
        end
      end
    end
  end
end
