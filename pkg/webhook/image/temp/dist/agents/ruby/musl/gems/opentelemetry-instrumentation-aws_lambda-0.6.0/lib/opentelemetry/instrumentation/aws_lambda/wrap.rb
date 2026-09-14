# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsLambda
      # Helper module that can be used to wrap a lambda handler method
      module Wrap # rubocop:disable Metrics/ModuleLength
        AWS_TRIGGERS = ['aws:sqs', 'aws:s3', 'aws:sns', 'aws:dynamodb'].freeze
        DEFAULT_FLUSH_TIMEOUT = ENV.fetch('OTEL_INSTRUMENTATION_AWS_LAMBDA_FLUSH_TIMEOUT', '30000').to_i

        def instrument_handler(method, flush_timeout: DEFAULT_FLUSH_TIMEOUT)
          raise ArgumentError, "#{method} is not a method of #{name}" unless respond_to?(method)

          uninstrumented_method = "#{method}_without_instrumentation"
          singleton_class.alias_method uninstrumented_method, method

          handler = "#{name}.#{method}"

          define_singleton_method(method) do |event:, context:|
            wrap_lambda(event: event, context: context, handler: handler, flush_timeout: flush_timeout) { public_send(uninstrumented_method, event: event, context: context) }
          end
        end

        # Try to record and re-raise any exception from the wrapped function handler
        # Instrumentation should never raise its own exception
        def wrap_lambda(event:, context:, handler:, flush_timeout: DEFAULT_FLUSH_TIMEOUT)
          parent_context = extract_parent_context(event)

          span_kind = if event['Records'] && AWS_TRIGGERS.include?(event['Records'].dig(0, 'eventSource'))
                        :consumer
                      else
                        :server
                      end

          original_handler_error = nil
          original_response = nil
          OpenTelemetry::Context.with_current(parent_context) do
            tracer.in_span(handler, attributes: otel_attributes(event, context), kind: span_kind) do |span|
              begin
                response = yield

                if span.recording? && !span.attributes.key?(OpenTelemetry::SemanticConventions::Trace::HTTP_STATUS_CODE)
                  status_code = response['statusCode'] || response[:statusCode] if response.is_a?(Hash)
                  span.set_attribute(OpenTelemetry::SemanticConventions::Trace::HTTP_STATUS_CODE, status_code) if status_code
                end
              rescue StandardError => e
                original_handler_error = e
              ensure
                original_response = response
              end
              if original_handler_error
                span.record_exception(original_handler_error)
                span.status = OpenTelemetry::Trace::Status.error(original_handler_error.message)
              end
            end
          end

          OpenTelemetry.tracer_provider.force_flush(timeout: flush_timeout)
          OpenTelemetry.meter_provider.force_flush(timeout: flush_timeout) if OpenTelemetry.respond_to?(:meter_provider)

          raise original_handler_error if original_handler_error

          original_response
        end

        def instrumentation_config
          AwsLambda::Instrumentation.instance.config
        end

        def tracer
          AwsLambda::Instrumentation.instance.tracer
        end

        private

        # Extract parent context from request headers
        # Downcase Traceparent and Tracestate because TraceContext::TextMapPropagator's TRACEPARENT_KEY and TRACESTATE_KEY are all lowercase
        # If any error occur, rescue and give empty context
        def extract_parent_context(event)
          headers = event['headers'] || {}
          headers.transform_keys! do |key|
            %w[Traceparent Tracestate].include?(key) ? key.downcase : key
          end

          OpenTelemetry.propagation.extract(
            headers,
            getter: OpenTelemetry::Context::Propagation.text_map_getter
          )
        rescue StandardError => e
          OpenTelemetry.logger.error("aws-lambda instrumentation exception occurred while extracting the parent context: #{e.message}")
          OpenTelemetry::Context.empty
        end

        # lambda event version 1.0 and version 2.0
        # https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
        def v1_proxy_attributes(event)
          attributes = {
            OpenTelemetry::SemanticConventions::Trace::HTTP_METHOD => event['httpMethod'],
            OpenTelemetry::SemanticConventions::Trace::HTTP_ROUTE => event['resource'],
            OpenTelemetry::SemanticConventions::Trace::HTTP_TARGET => event['resource']
          }
          attributes[OpenTelemetry::SemanticConventions::Trace::HTTP_TARGET] += "?#{event['queryStringParameters']}" if event['queryStringParameters']

          headers = event['headers']
          if headers
            attributes[OpenTelemetry::SemanticConventions::Trace::HTTP_USER_AGENT] = headers['User-Agent']
            attributes[OpenTelemetry::SemanticConventions::Trace::HTTP_SCHEME]     = headers['X-Forwarded-Proto']
            attributes[OpenTelemetry::SemanticConventions::Trace::NET_HOST_NAME]   = headers['Host']
          end
          attributes
        end

        def v2_proxy_attributes(event)
          request_context = event['requestContext']
          attributes = {
            OpenTelemetry::SemanticConventions::Trace::NET_HOST_NAME => request_context['domainName'],
            OpenTelemetry::SemanticConventions::Trace::HTTP_METHOD => request_context['http']['method'],
            OpenTelemetry::SemanticConventions::Trace::HTTP_USER_AGENT => request_context['http']['userAgent'],
            OpenTelemetry::SemanticConventions::Trace::HTTP_ROUTE => request_context['http']['path'],
            OpenTelemetry::SemanticConventions::Trace::HTTP_TARGET => request_context['http']['path']
          }
          attributes[OpenTelemetry::SemanticConventions::Trace::HTTP_TARGET] += "?#{event['rawQueryString']}" if event['rawQueryString']
          attributes
        end

        # fass.trigger set to http: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/faas/aws-lambda.md#api-gateway
        # TODO: need to update Semantic Conventions for invocation_id, trigger and resource_id
        def otel_attributes(event, context)
          span_attributes = {}
          span_attributes['faas.invocation_id'] = context.aws_request_id
          span_attributes['cloud.resource_id'] = context.invoked_function_arn
          span_attributes[OpenTelemetry::SemanticConventions::Trace::AWS_LAMBDA_INVOKED_ARN] = context.invoked_function_arn
          span_attributes[OpenTelemetry::SemanticConventions::Resource::CLOUD_ACCOUNT_ID] = context.invoked_function_arn.split(':')[4]

          if event['requestContext']
            request_attributes = event['version'] == '2.0' ? v2_proxy_attributes(event) : v1_proxy_attributes(event)
            request_attributes[OpenTelemetry::SemanticConventions::Trace::FAAS_TRIGGER] = 'http'
            span_attributes.merge!(request_attributes)
          end

          if event['Records']
            trigger_attributes = trigger_type_attributes(event)
            span_attributes.merge!(trigger_attributes)
          end

          span_attributes
        rescue StandardError => e
          OpenTelemetry.logger.error("aws-lambda instrumentation exception occurred while preparing span attributes: #{e.message}")
          {}
        end

        # sqs spec for lambda: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/faas/aws-lambda.md#sqs
        # current there is no spec for 'aws:sns', 'aws:s3' and 'aws:dynamodb'
        def trigger_type_attributes(event)
          attributes = {}
          case event['Records'].dig(0, 'eventSource')
          when 'aws:sqs'
            attributes[OpenTelemetry::SemanticConventions::Trace::FAAS_TRIGGER] = 'pubsub'
            attributes[OpenTelemetry::SemanticConventions::Trace::MESSAGING_OPERATION] = 'process'
            attributes[OpenTelemetry::SemanticConventions::Trace::MESSAGING_SYSTEM] = 'AmazonSQS'
          end
          attributes
        end
      end
    end
  end
end
