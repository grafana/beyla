# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Dalli
      module Patches
        # Module to prepend to Dalli::Server (or Dalli::Protocol::Binary/Meta in 3.0+) for instrumentation
        module Server
          def request(op, *args) # rubocop:disable Naming/MethodParameterName
            operation = Utils.opname(op, multi?)
            attributes = {
              'db.system' => 'memcached',
              'db.operation' => operation,
              'net.peer.name' => hostname
            }
            attributes['net.peer.port'] = port if port

            if config[:db_statement] == :include
              attributes['db.statement'] = Utils.format_command(operation, args)
            elsif config[:db_statement] == :obfuscate
              attributes['db.statement'] = "#{operation} ?"
            end

            attributes['peer.service'] = config[:peer_service] if config[:peer_service]
            tracer.in_span(operation, attributes: attributes, kind: :client) do
              super
            end
          end

          private

          def tracer
            Dalli::Instrumentation.instance.tracer
          end

          def config
            Dalli::Instrumentation.instance.config
          end
        end
      end
    end
  end
end
