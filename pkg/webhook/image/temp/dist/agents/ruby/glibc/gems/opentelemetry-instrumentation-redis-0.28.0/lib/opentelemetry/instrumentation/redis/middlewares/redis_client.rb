# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Redis
      module Middlewares
        # Adapter for redis-client instrumentation interface
        module RedisClientInstrumentation
          MAX_STATEMENT_LENGTH = 500
          private_constant :MAX_STATEMENT_LENGTH

          def call(command, redis_config)
            return super unless instrumentation.config[:trace_root_spans] || OpenTelemetry::Trace.current_span.context.valid?

            attributes = span_attributes(redis_config)

            attributes['db.statement'] = serialize_commands([command]) unless instrumentation.config[:db_statement] == :omit

            span_name = command[0].to_s.upcase
            instrumentation.tracer.in_span(span_name, attributes: attributes, kind: :client) do
              super
            end
          end

          def call_pipelined(commands, redis_config)
            return super unless instrumentation.config[:trace_root_spans] || OpenTelemetry::Trace.current_span.context.valid?

            attributes = span_attributes(redis_config)

            attributes['db.statement'] = serialize_commands(commands) unless instrumentation.config[:db_statement] == :omit

            instrumentation.tracer.in_span('PIPELINED', attributes: attributes, kind: :client) do
              super
            end
          end

          private

          def span_attributes(redis_config)
            attributes = {
              'db.system' => 'redis',
              'net.peer.name' => redis_config.host,
              'net.peer.port' => redis_config.port
            }

            attributes['db.redis.database_index'] = redis_config.db unless redis_config.db.zero?
            attributes['peer.service'] = instrumentation.config[:peer_service] if instrumentation.config[:peer_service]
            attributes.merge!(OpenTelemetry::Instrumentation::Redis.attributes)
            attributes
          end

          def serialize_commands(commands)
            obfuscate = instrumentation.config[:db_statement] == :obfuscate

            serialized_commands = commands.map do |command|
              # If we receive an authentication request command we want to obfuscate it
              if obfuscate || command[0].match?(/\A(AUTH|HELLO)\z/i)
                command[0].to_s.upcase + (' ?' * (command.size - 1))
              else
                command_copy = command.dup
                command_copy[0] = command_copy[0].to_s.upcase
                command_copy.join(' ')
              end
            end.join("\n")
            serialized_commands = OpenTelemetry::Common::Utilities.truncate(serialized_commands, MAX_STATEMENT_LENGTH)
            OpenTelemetry::Common::Utilities.utf8_encode(serialized_commands, binary: true)
          end

          def instrumentation
            Redis::Instrumentation.instance
          end
        end
      end
    end
  end
end
