# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module Koala
      # The Instrumentation class contains logic to detect and install the Koala instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          require_dependencies
          patch
        end

        present do
          !defined?(::Koala).nil?
        end

        private

        def require_dependencies
          require_relative 'patches/instrumentation'
        end

        def patch
          ::Koala::Facebook::API.prepend(Patches::Api)
        end
      end
    end
  end
end
