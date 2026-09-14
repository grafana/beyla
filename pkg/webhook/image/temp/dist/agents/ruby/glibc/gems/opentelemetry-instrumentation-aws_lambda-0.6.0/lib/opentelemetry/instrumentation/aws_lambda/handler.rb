# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsLambda
      # Handler class that creates a span around the _HANDLER
      class Handler
        extend OpenTelemetry::Instrumentation::AwsLambda::Wrap

        attr_reader :handler_method, :handler_class

        # anytime when the code in a Lambda function is updated or the functional configuration is changed,
        # the next invocation results in a cold start; therefore these instance variables will be up-to-date
        def initialize
          @flush_timeout    = ENV.fetch('OTEL_INSTRUMENTATION_AWS_LAMBDA_FLUSH_TIMEOUT', '30000').to_i
          @original_handler = ENV['ORIG_HANDLER'] || ENV['_HANDLER'] || ''
          @handler_class    = nil
          @handler_method   = nil
          @handler_file     = nil

          resolve_original_handler
        end

        # Try to record and re-raise any exception from the wrapped function handler
        # Instrumentation should never raise its own exception
        def call_wrapped(event:, context:)
          self.class.wrap_lambda(event: event, context: context, handler: @original_handler, flush_timeout: @flush_timeout) do
            call_original_handler(event: event, context: context)
          end
        end

        private

        # we don't expose error if our code cause issue that block user's code
        def resolve_original_handler
          original_handler_parts = @original_handler.split('.')
          if original_handler_parts.size == 2
            @handler_file, @handler_method = original_handler_parts
          elsif original_handler_parts.size == 3
            @handler_file, @handler_class, @handler_method = original_handler_parts
          else
            OpenTelemetry.logger.error("aws-lambda instrumentation: Invalid handler #{original_handler}, must be of form FILENAME.METHOD or FILENAME.CLASS.METHOD.")
          end

          require @handler_file if @handler_file
        end

        def call_original_handler(event:, context:)
          if @handler_class
            Kernel.const_get(@handler_class).send(@handler_method, event: event, context: context)
          else
            __send__(@handler_method, event: event, context: context)
          end
        end
      end
    end
  end
end
