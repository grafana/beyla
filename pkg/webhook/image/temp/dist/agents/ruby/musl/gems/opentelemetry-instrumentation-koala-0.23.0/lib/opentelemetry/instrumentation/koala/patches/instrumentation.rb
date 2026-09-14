# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Koala
      module Patches
        # Module to prepend to Koala::Facebook::API for instrumentation
        module Api
          def graph_call(path, args = {}, verb = 'get', options = {}, &)
            OpenTelemetry::Common::HTTP::ClientContext.with_attributes('peer.service' => 'facebook', 'koala.verb' => verb, 'koala.path' => path) do
              super
            end
          end
        end
      end
    end
  end
end
