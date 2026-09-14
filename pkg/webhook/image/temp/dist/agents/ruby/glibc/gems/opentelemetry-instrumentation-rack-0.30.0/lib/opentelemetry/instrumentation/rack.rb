# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry'
require 'opentelemetry-instrumentation-base'

module OpenTelemetry
  module Instrumentation
    # Contains the OpenTelemetry instrumentation for the Rack gem
    module Rack
      extend self

      CURRENT_SPAN_KEY = Context.create_key('current-span')
      private_constant :CURRENT_SPAN_KEY

      # Returns the current span from the current or provided context
      #
      # @param [optional Context] context The context to lookup the current
      #   {Span} from. Defaults to Context.current
      def current_span(context = nil)
        context ||= Context.current
        context.value(CURRENT_SPAN_KEY) || OpenTelemetry::Trace::Span::INVALID
      end

      # Returns a context containing the span, derived from the optional parent
      # context, or the current context if one was not provided.
      #
      # @param [optional Context] context The context to use as the parent for
      #   the returned context
      def context_with_span(span, parent_context: Context.current)
        parent_context.set_value(CURRENT_SPAN_KEY, span)
      end

      # Activates/deactivates the Span within the current Context, which makes the "current span"
      # available implicitly.
      #
      # On exit, the Span that was active before calling this method will be reactivated.
      #
      # @param [Span] span the span to activate
      # @yield [span, context] yields span and a context containing the span to the block.
      def with_span(span)
        Context.with_value(CURRENT_SPAN_KEY, span) { |c, s| yield s, c }
      end
    end
  end
end

require_relative 'rack/instrumentation'
require_relative 'rack/util'
require_relative 'rack/version'
