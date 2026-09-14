# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Redis
      # The Instrumentation class contains logic to detect and install the Redis
      # instrumentation
      class Instrumentation < OpenTelemetry::Instrumentation::Base
        install do |_config|
          require_dependencies
          patch_client
        end

        present do
          defined?(::Redis) || defined?(::RedisClient)
        end

        option :peer_service,                 default: nil,   validate: :string
        option :trace_root_spans,             default: true,  validate: :boolean
        option :db_statement,                 default: :obfuscate, validate: %I[omit include obfuscate]

        private

        def require_dependencies
          require_relative 'patches/redis_v4_client' if defined?(::Redis) && ::Redis::VERSION < '5'
          require_relative 'middlewares/redis_client' if defined?(::RedisClient)
        end

        def patch_client
          ::RedisClient.register(Middlewares::RedisClientInstrumentation) if defined?(::RedisClient)
          ::Redis::Client.prepend(Patches::RedisV4Client) if defined?(::Redis) && ::Redis::VERSION < '5'
        end
      end
    end
  end
end
