# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Mongo
      # Serializes a Mongo command object to be added to the trace
      class CommandSerializer
        MASK_VALUE = '?'
        ELLIPSES = '...'

        attr_reader :command, :command_name, :collection, :payload

        def initialize(command, obfuscate)
          @command = command
          @command_name, @collection = command.first
          @obfuscate = obfuscate
          @payload = {}
        end

        def serialize
          build_payload
          payload.to_json.freeze unless payload.empty?
        end

        private

        def build_payload
          build_command
          build_updates
          build_deletes
          build_pipeline
        end

        def build_command
          add_val(payload, command, 'key')
          add_map(payload, command, 'query')
          add_map(payload, command, 'filter')
          add_val(payload, command, 'sort')
          add_val(payload, command, 'new')
          add_map(payload, command, 'update') if command_name == 'findAndModify'
          add_val(payload, command, 'remove')
        end

        def build_updates
          updates = command['updates']
          return unless updates

          update = updates[0]
          update_payload = {}
          add_map(update_payload, update, 'q')
          add_map(update_payload, update, 'u')
          add_val(update_payload, update, 'multi')
          add_val(update_payload, update, 'upsert')
          payload['updates'] = [update_payload]
          payload['updates'] << ELLIPSES if updates.length > 1
        end

        def build_deletes
          deletes = command['deletes']
          return unless deletes

          delete = deletes[0]
          delete_payload = {}
          add_map(delete_payload, delete, 'q')
          add_map(delete_payload, delete, 'limit')
          payload['deletes'] = [delete_payload]
          payload['deletes'] << ELLIPSES if deletes.length > 1
        end

        def build_pipeline
          pipeline = command['pipeline']
          return unless pipeline

          payload['pipeline'] = pipeline.map { |x| mask(x) }
        end

        def add_val(payload, command, key)
          return unless command.key?(key)

          value = command[key]
          payload[key] = value
        end

        def add_map(payload, command, key)
          value = command[key]
          return unless value.is_a?(Hash) && !value.empty?

          payload[key] = mask(value)
        end

        def mask(hash)
          hash.each_with_object({}) do |(k, v), h|
            value = if v.is_a?(Hash)
                      mask(v)
                    elsif @obfuscate
                      MASK_VALUE
                    else
                      v
                    end
            h[k] = value
          end
        end
      end
    end
  end
end
