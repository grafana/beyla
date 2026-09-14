# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    # rubocop:disable Style/Documentation
    module ActiveSupport
      LEGACY_NAME_FORMATTER = ->(name) { name.split('.')[0..1].reverse.join(' ') }

      # rubocop:disable Metrics/ParameterLists
      # The SpanSubscriber is a special ActiveSupport::Notification subscription
      # handler which turns notifications into generic spans, taking care to handle
      # context appropriately.
      #
      # @param tracer [OpenTelemetry::Trace::Tracer] tracer used to create spans
      # @param pattern [String, Regexp] ActiveSupport notification pattern
      # @param notification_payload_transform [Callable, nil] optional callable
      #   that receives the notification payload and returns a Hash of span
      #   attributes
      # @param disallowed_notification_payload_keys [Array<String>, nil] notification
      #   payload keys that should not be recorded as span attributes
      # @param kind [Symbol, nil] span kind to use for generated spans
      # @param span_name_formatter [Callable, nil] optional callable that receives
      #   the notification name and returns the span name

      # A very hacky way to make sure that OpenTelemetry::Instrumentation::ActiveSupport::SpanSubscriber
      # gets invoked first
      # Rails 6+ https://github.com/rails/rails/blob/0f0ec9908e25af36df2d937dc431f626a4102b3d/activesupport/lib/active_support/notifications/fanout.rb#L51
      def self.subscribe(
        tracer,
        pattern,
        notification_payload_transform = nil,
        disallowed_notification_payload_keys = nil,
        kind: nil,
        span_name_formatter: nil
      )
        subscriber = OpenTelemetry::Instrumentation::ActiveSupport::SpanSubscriber.new(
          pattern: pattern,
          tracer: tracer,
          notification_payload_transform: notification_payload_transform,
          disallowed_notification_payload_keys: disallowed_notification_payload_keys,
          kind: kind,
          span_name_formatter: span_name_formatter
        )

        subscriber_object = ::ActiveSupport::Notifications.subscribe(pattern, subscriber)

        # this can be removed once we drop support for Rails < 7.2
        # see https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/707 for more context
        if ::ActiveSupport::Notifications.notifier.respond_to?(:synchronize)
          ::ActiveSupport::Notifications.notifier.synchronize do
            subscribers = ::ActiveSupport::Notifications.notifier.instance_variable_get(:@string_subscribers)[pattern]

            if subscribers.nil?
              OpenTelemetry.handle_error(
                message: 'Unable to move OTEL ActiveSupport Notifications subscriber to the front of the notifications list which may cause incomplete traces.' \
                         'Please report an issue here: ' \
                         'https://github.com/open-telemetry/opentelemetry-ruby-contrib/issues/new?labels=bug&template=bug_report.md&title=ActiveSupport%20Notifications%20subscribers%20list%20is%20nil'
              )
            else
              subscribers.unshift(
                subscribers.delete(subscriber_object)
              )
            end
          end
        end
        subscriber_object
      end

      # rubocop:enable Metrics/ParameterLists
      class SpanSubscriber
        ALWAYS_VALID_PAYLOAD_TYPES = [TrueClass, FalseClass, String, Numeric, Symbol].freeze

        # rubocop:disable Metrics/ParameterLists
        def initialize(pattern:, tracer:, notification_payload_transform: nil, disallowed_notification_payload_keys: nil, kind: nil, span_name_formatter: nil)
          @pattern = pattern
          @tracer = tracer
          @notification_payload_transform = notification_payload_transform
          @disallowed_notification_payload_keys = Array(disallowed_notification_payload_keys)
          @kind = kind || :internal
          @span_name_formatter = span_name_formatter
        end
        # rubocop:enable Metrics/ParameterLists

        def start(name, id, payload)
          span = @tracer.start_span(safe_span_name_for(name), kind: @kind)
          token = OpenTelemetry::Context.attach(
            OpenTelemetry::Trace.context_with_span(span)
          )
          payload[:__opentelemetry_span] = span
          payload[:__opentelemetry_ctx_token] = token

          [span, token]
        end

        def finish(name, id, payload)
          span = payload.delete(:__opentelemetry_span)
          token = payload.delete(:__opentelemetry_ctx_token)
          return unless span && token

          attrs = transform_payload(payload).each_with_object({}) do |(k, v), accum|
            accum[k.to_s] = sanitized_value(v) if valid_payload_key?(k) && valid_payload_value?(v)
          end

          span.add_attributes(attrs)

          if (e = payload[:exception_object])
            span.record_exception(e)
            span.status = OpenTelemetry::Trace::Status.error("Unhandled exception of type: #{e.class}")
          end

          span.finish
          OpenTelemetry::Context.detach(token)
        end

        private

        def transform_payload(payload)
          return payload if @notification_payload_transform.nil?

          @notification_payload_transform.call(payload)
        end

        def valid_payload_key?(key)
          %i[exception exception_object].none?(key) && @disallowed_notification_payload_keys.none?(key)
        end

        def valid_payload_value?(value)
          if value.is_a?(Array)
            return true if value.empty?

            value.map(&:class).uniq.size == 1 && ALWAYS_VALID_PAYLOAD_TYPES.any? { |t| value.first.is_a?(t) }
          else
            ALWAYS_VALID_PAYLOAD_TYPES.any? { |t| value.is_a?(t) }
          end
        end

        # We'll accept symbols as values, but stringify them; and we'll stringify symbols within an array.
        def sanitized_value(value)
          if value.is_a?(Array)
            value.map { |v| v.is_a?(Symbol) ? v.to_s : v }
          elsif value.is_a?(Symbol)
            value.to_s
          else
            value
          end
        end

        # Helper method to try an shield the span name formatter from errors
        #
        # It wraps the user supplied formatter in a rescue block and returns the original name if a StandardError is raised by the formatter
        def safe_span_name_for(name)
          @span_name_formatter&.call(name) || name
        rescue StandardError => e
          OpenTelemetry.handle_error(exception: e, message: 'Error calling span_name_formatter. Using default span name.')
          name
        end
      end
    end
  end
  # rubocop:enable Style/Documentation
end
