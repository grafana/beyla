# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module SDK
    module Metrics
      module Instrument
        # {AsynchronousInstrument} contains the common functionality shared across
        # the asynchronous instruments SDK instruments.
        class AsynchronousInstrument
          NOOP_EXEMPLAR_RESERVOIR = Exemplar::NoopExemplarReservoir.new

          def initialize(name, unit, description, callback, instrumentation_scope, meter_provider, exemplar_filter, exemplar_reservoir)
            @name = name
            @unit = unit
            @description = description
            @instrumentation_scope = instrumentation_scope
            @meter_provider = meter_provider
            @metric_streams = []
            @callbacks = []
            @timeout   = nil
            @attributes = {}
            @exemplar_filter = exemplar_filter || meter_provider.exemplar_filter
            @exemplar_reservoir = exemplar_reservoir

            init_callback(callback)
            meter_provider.register_asynchronous_instrument(self)
          end

          # @api private
          def register_with_new_metric_store(metric_store, aggregation: default_aggregation)
            ms = OpenTelemetry::SDK::Metrics::State::AsynchronousMetricStream.new(
              @name,
              @description,
              @unit,
              instrument_kind,
              @meter_provider,
              @instrumentation_scope,
              aggregation,
              @callbacks,
              @timeout,
              @attributes,
              @exemplar_filter,
              @exemplar_reservoir
            )
            @metric_streams << ms
            metric_store.add_metric_stream(ms)
          end

          # The API MUST support creation of asynchronous instruments by passing zero or more callback functions
          # to be permanently registered to the newly created instrument.
          def init_callback(callback)
            if callback.instance_of?(Proc)
              @callbacks << callback
            elsif callback.instance_of?(Array)
              callback.each { |cb| @callbacks << cb if cb.instance_of?(Proc) }
            else
              OpenTelemetry.logger.warn "Only accept single Proc or Array of Proc for initialization with callback (given callback #{callback.class}"
            end
          end

          # Where the API supports registration of callback functions after asynchronous instrumentation creation,
          # the user MUST be able to undo registration of the specific callback after its registration by some means.
          def register_callback(callback)
            if callback.instance_of?(Proc)
              @callbacks << callback
              callback
            else
              OpenTelemetry.logger.warn "Only accept single Proc for registering callback (given callback #{callback.class}"
            end
          end

          def unregister(callback)
            @callbacks.delete(callback)
          end

          def timeout(timeout)
            @timeout = timeout
          end

          def add_attributes(attributes)
            @attributes.merge!(attributes) if attributes.instance_of?(Hash)
          end

          private

          # update the observed value (after calling observe)
          # invoke callback will execute callback and export metric_data that is observed
          def update(timeout, attributes)
            @metric_streams.each { |ms| ms.invoke_callback(timeout, attributes) }
          end

          # Adding the exemplar to reservoir
          # Only record the exemplar if exemplar_filter decide to sample/record it
          def exemplar_offer(value, attributes)
            context = OpenTelemetry::Context.current
            time = OpenTelemetry::Common::Utilities.time_in_nanoseconds
            return unless @exemplar_filter.should_sample?(value, time, attributes, context)

            @exemplar_reservoir.offer(value: value, timestamp: time, attributes: attributes, context: context)
          end
        end
      end
    end
  end
end
