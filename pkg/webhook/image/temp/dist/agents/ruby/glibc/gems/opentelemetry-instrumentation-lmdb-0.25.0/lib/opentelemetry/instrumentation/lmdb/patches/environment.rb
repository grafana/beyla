# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module LMDB
      module Patches
        # Module to prepend to LMDB::Environment for instrumentation
        module Environment
          def transaction(*args)
            attributes = { 'db.system' => 'lmdb' }
            attributes['peer.service'] = config[:peer_service] if config[:peer_service]

            tracer.in_span('TRANSACTION', attributes: attributes) do
              super
            end
          end

          private

          def config
            LMDB::Instrumentation.instance.config
          end

          def tracer
            LMDB::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
