# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Dalli
      # Utility functions
      module Utils
        extend self

        STRING_PLACEHOLDER = ''.encode(::Encoding::UTF_8).freeze
        CMD_MAX_LEN = 500

        OPNAME_MAPPING = {
          'get' => 'get',
          'cas' => 'get',
          'set' => 'set',
          'add' => 'add',
          'replace' => 'replace',
          'delete' => 'delete',
          'incr' => 'incr',
          'decr' => 'decr',
          'flush' => 'flush',
          'write_noop' => 'noop',
          'version' => 'version',
          'send_multiget' => 'getkq',
          # TODO: add better support for PipelinedGetter
          # In dalli 3.1, multiget has been refactored to use a more robust PipelinedGetter class.
          # The `pipelined_get` method has been introduced to the Dalli::Server to support this new class.
          # If PipelinedGetter makes instrumentation of multi operations easier, we should then migrate
          # instrumentation to Dalli::Client, since it seems to be a more stable chokepoint.
          # For now we're just ensuring we support this new Dalli::Server method.
          'pipelined_get' => 'getkq',
          'append' => 'append',
          'prepend' => 'prepend',
          'stats' => 'stat',
          'reset_stats' => 'stat',
          'multi_set' => 'setq',
          'multi_add' => 'addq',
          'multi_replace' => 'replaceq',
          'multi_delete' => 'deleteq',
          'touch' => 'touch',
          'gat' => 'gat'
          # 'sasl_authentication' => 'auth_negotiation',
          # 'sasl_authentication' => 'auth_request',
        }.freeze

        def opname(operation, multi)
          lookup_name = multi ? "multi_#{operation}" : operation.to_s
          OPNAME_MAPPING[lookup_name] || operation.to_s
        end

        def format_command(operation, args)
          placeholder = "#{operation} BLOB (OMITTED)"

          command = +operation.to_s
          args.flatten.each do |arg|
            str = arg.to_s
            if str.bytesize >= CMD_MAX_LEN
              command << ' BLOB (OMITTED)'
            elsif !str.empty?
              command << ' ' << str
            end
          end

          command = OpenTelemetry::Common::Utilities.utf8_encode(command, binary: true, placeholder: placeholder)
          OpenTelemetry::Common::Utilities.truncate(command, CMD_MAX_LEN)
        rescue StandardError => e
          OpenTelemetry.logger.debug("Error sanitizing Dalli operation: #{e}")
          placeholder
        end
      end
    end
  end
end
