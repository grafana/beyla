# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsLambda
      # Instrumentation class that detects and installs the AwsLambda instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          require_dependencies
        end

        # determine if current environment is lambda by checking _HANLDER or ORIG_HANDLER
        present do
          ENV.key?('_HANDLER') || ENV.key?('ORIG_HANDLER')
        end

        private

        def require_dependencies
          require_relative 'wrap'
          require_relative 'handler'
        end
      end
    end
  end
end
