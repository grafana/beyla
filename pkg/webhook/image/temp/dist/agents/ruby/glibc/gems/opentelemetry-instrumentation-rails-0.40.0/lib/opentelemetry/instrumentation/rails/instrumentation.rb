# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module Rails
      # The Instrumentation class contains logic to detect and install the Rails
      # instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        MINIMUM_VERSION = Gem::Version.new('7')

        # This gem requires the instrumentation gems for the different
        # components of Rails, as a result it does not have any explicit
        # work to do in the install step.
        install { true }
        present { defined?(::Rails) }
        compatible { gem_version >= MINIMUM_VERSION }

        private

        def gem_version
          ::Rails.gem_version
        end
      end
    end
  end
end
