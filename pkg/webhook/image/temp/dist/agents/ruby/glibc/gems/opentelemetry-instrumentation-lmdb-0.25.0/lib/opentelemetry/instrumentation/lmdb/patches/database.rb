# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'

module OpenTelemetry
  module Instrumentation
    module LMDB
      module Patches
        # Module to prepend to LMDB::Database for instrumentation
        module Database
          STATEMENT_MAX_LENGTH = 500

          def get(key)
            attributes = { 'db.system' => 'lmdb' }
            attributes['db.statement'] = formatted_statement('GET', "GET #{key}") if config[:db_statement] == :include
            attributes['peer.service'] = config[:peer_service] if config[:peer_service]

            tracer.in_span("GET #{key}", attributes: attributes, kind: :client) do
              super
            end
          end

          def delete(key, value = nil)
            attributes = { 'db.system' => 'lmdb' }
            attributes['db.statement'] = formatted_statement('DELETE', "DELETE #{key} #{value}".strip) if config[:db_statement] == :include
            attributes['peer.service'] = config[:peer_service] if config[:peer_service]

            tracer.in_span("DELETE #{key}", attributes: attributes, kind: :client) do
              super
            end
          end

          def put(key, value)
            attributes = { 'db.system' => 'lmdb' }
            attributes['db.statement'] = formatted_statement('PUT', "PUT #{key} #{value}") if config[:db_statement] == :include
            attributes['peer.service'] = config[:peer_service] if config[:peer_service]

            tracer.in_span("PUT #{key}", attributes: attributes, kind: :client) do
              super
            end
          end

          def clear
            attributes = { 'db.system' => 'lmdb' }
            attributes['db.statement'] = 'CLEAR' if config[:db_statement] == :include
            attributes['peer.service'] = config[:peer_service] if config[:peer_service]

            tracer.in_span('CLEAR', attributes: attributes, kind: :client) do
              super
            end
          end

          private

          def formatted_statement(operation, statement)
            statement = OpenTelemetry::Common::Utilities.truncate(statement, STATEMENT_MAX_LENGTH)
            OpenTelemetry::Common::Utilities.utf8_encode(statement)
          rescue StandardError => e
            OpenTelemetry.logger.debug("non formattable LMDB statement #{statement}: #{e}")
            "#{operation} BLOB (OMITTED)"
          end

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
