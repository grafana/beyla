# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative 'command_serializer'

module OpenTelemetry
  module Instrumentation
    module Mongo
      # Event handler class for Mongo Ruby driver
      class Subscriber
        THREAD_KEY = :__opentelemetry_mongo_spans__

        def started(event)
          # start a trace and store it in the current thread; using the `operation_id`
          # is safe since it's a unique id used to link events together. Also only one
          # thread is involved in this execution so thread-local storage should be safe. Reference:
          # https://github.com/mongodb/mongo-ruby-driver/blob/master/lib/mongo/monitoring.rb#L70
          # https://github.com/mongodb/mongo-ruby-driver/blob/master/lib/mongo/monitoring/publishable.rb#L38-L56

          collection = get_collection(event.command)

          attributes = {
            'db.system' => 'mongodb',
            'db.name' => event.database_name,
            'db.operation' => event.command_name,
            'net.peer.name' => event.address.host,
            'net.peer.port' => event.address.port
          }

          config = Mongo::Instrumentation.instance.config
          attributes['peer.service'] = config[:peer_service] if config[:peer_service]
          # attributes['db.statement'] = CommandSerializer.new(event.command).serialize
          omit = config[:db_statement] == :omit
          obfuscate = config[:db_statement] == :obfuscate
          attributes['db.statement'] = CommandSerializer.new(event.command, obfuscate).serialize unless omit
          attributes['db.mongodb.collection'] = collection if collection
          attributes.compact!

          span = tracer.start_span(span_name(collection, event.command_name), attributes: attributes, kind: :client)
          set_span(event, span)
        end

        def failed(event)
          finish_event('failed', event) do |span|
            if event.is_a?(::Mongo::Monitoring::Event::CommandFailed)
              span.add_event('exception',
                             attributes: {
                               'exception.type' => 'CommandFailed',
                               'exception.message' => event.message
                             })
            end
          end
        end

        def succeeded(event)
          finish_event('succeeded', event)
        end

        private

        def finish_event(name, event)
          span = get_span(event)
          return unless span

          yield span if block_given?
        rescue StandardError => e
          OpenTelemetry.logger.debug("error when handling MongoDB '#{name}' event: #{e}")
        ensure
          # finish span to prevent leak and remove it from thread storage
          span&.finish
          clear_span(event)
        end

        def span_name(collection, command_name)
          return command_name unless collection

          "#{collection}.#{command_name}"
        end

        def get_collection(command)
          collection = command.values.first
          collection if collection.is_a?(String)
        end

        def get_span(event)
          Thread.current[THREAD_KEY]&.[](event.request_id)
        end

        def set_span(event, span)
          Thread.current[THREAD_KEY] ||= {}
          Thread.current[THREAD_KEY][event.request_id] = span
        end

        def clear_span(event)
          Thread.current[THREAD_KEY]&.delete(event.request_id)
        end

        def tracer
          Mongo::Instrumentation.instance.tracer
        end
      end
    end
  end
end
