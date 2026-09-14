# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsSdk
      # Utility module that contains shared methods between AwsSdk and Telemetry handlers
      module HandlerHelper
        class << self
          def instrumentation_config
            AwsSdk::Instrumentation.instance.config
          end

          def skip_internal_instrumentation?
            instrumentation_config[:enable_internal_instrumentation] == false
          end

          def client_method(service_id, context)
            "#{service_id}.#{context.operation.name}".delete(' ')
          end

          def span_attributes(context, client_method, service_id, legacy: false)
            {
              'aws.region' => context.config.region,
              OpenTelemetry::SemanticConventions::Trace::CODE_FUNCTION => context.operation_name.to_s,
              OpenTelemetry::SemanticConventions::Trace::CODE_NAMESPACE => 'Aws::Plugins::Telemetry',
              OpenTelemetry::SemanticConventions::Trace::RPC_METHOD => context.operation.name,
              OpenTelemetry::SemanticConventions::Trace::RPC_SERVICE => service_id,
              OpenTelemetry::SemanticConventions::Trace::RPC_SYSTEM => 'aws-api'
            }.tap do |attrs|
              attrs[OpenTelemetry::SemanticConventions::Trace::CODE_NAMESPACE] = 'Aws::Plugins::AwsSdk' if legacy
              attrs[SemanticConventions::Trace::DB_SYSTEM] = 'dynamodb' if service_id == 'DynamoDB'

              MessagingHelper.apply_span_attributes(context, attrs, client_method, service_id) if MessagingHelper::SUPPORTED_SERVICES.include?(service_id)
            end
          end

          def span_kind(client_method, service_id)
            case service_id
            when *MessagingHelper::SUPPORTED_SERVICES
              MessagingHelper.span_kind(client_method)
            else
              OpenTelemetry::Trace::SpanKind::CLIENT
            end
          end

          def span_name(context, client_method, service_id, legacy: false)
            case service_id
            when *MessagingHelper::SUPPORTED_SERVICES
              if legacy
                MessagingHelper.legacy_span_name(context, client_method)
              else
                MessagingHelper.span_name(context, client_method)
              end
            else
              client_method
            end
          end

          def service_id(context, legacy: false)
            if legacy
              legacy_service_id(context)
            else
              context.config.api.metadata['serviceId'] ||
                context.config.api.metadata['serviceAbbreviation'] ||
                context.config.api.metadata['serviceFullName']
            end
          end

          private

          def legacy_service_id(context)
            # Support aws-sdk v2.0.x, which 'metadata' has a setter method only
            return context.client.class.to_s.split('::')[1] if ::Seahorse::Model::Api.instance_method(:metadata).parameters.length.positive?

            context.client.class.api.metadata['serviceId'] || context.client.class.to_s.split('::')[1]
          end
        end
      end
    end
  end
end
