# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative '../utils'

module OpenTelemetry
  module Instrumentation
    module RubyKafka
      module Patches
        # The Client module contains the instrumentation patch the Client#deliver_message and Client#each_message methods.
        module Client
          def deliver_message(value, topic:, key: nil, headers: {}, partition: nil, partition_key: nil, retries: 1)
            attributes = {
              'messaging.system' => 'kafka',
              'messaging.destination' => topic,
              'messaging.destination_kind' => 'topic'
            }

            message_key = Utils.extract_message_key(key)
            attributes['messaging.kafka.message_key'] = message_key if message_key

            attributes['messaging.kafka.partition'] = partition if partition

            tracer.in_span("#{topic} publish", attributes: attributes, kind: :producer) do
              OpenTelemetry.propagation.inject(headers)
              super
            end
          end

          def each_message(topic:, start_from_beginning: true, max_wait_time: 5, min_bytes: 1, max_bytes: 1_048_576, &block)
            super do |message|
              attributes = {
                'messaging.system' => 'kafka',
                'messaging.destination' => message.topic,
                'messaging.destination_kind' => 'topic',
                'messaging.kafka.partition' => message.partition
              }

              message_key = Utils.extract_message_key(message.key)
              attributes['messaging.kafka.message_key'] = message_key if message_key

              parent_context = OpenTelemetry.propagation.extract(message.headers)
              OpenTelemetry::Context.with_current(parent_context) do
                tracer.in_span("#{topic} process", attributes: attributes, kind: :consumer) do
                  yield message
                end
              end
            end
          end

          private

          def tracer
            RubyKafka::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
