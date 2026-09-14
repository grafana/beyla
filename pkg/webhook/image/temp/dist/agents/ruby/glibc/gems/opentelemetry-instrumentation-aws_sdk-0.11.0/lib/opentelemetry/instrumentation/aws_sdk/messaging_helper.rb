# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsSdk
      # An utility class to help SQS/SNS-related span attributes/context injection
      class MessagingHelper
        SUPPORTED_SERVICES = %w[SQS SNS].freeze
        class << self
          SQS_SEND_MESSAGE = 'SQS.SendMessage'
          SQS_SEND_MESSAGE_BATCH = 'SQS.SendMessageBatch'
          SQS_RECEIVE_MESSAGE = 'SQS.ReceiveMessage'
          SNS_PUBLISH = 'SNS.Publish'
          SEND_MESSAGE_CLIENT_METHODS = [SQS_SEND_MESSAGE, SQS_SEND_MESSAGE_BATCH, SNS_PUBLISH].freeze

          def supported_services
            SUPPORTED_SERVICES
          end

          def queue_name(context)
            topic_arn = context.params[:topic_arn]
            target_arn = context.params[:target_arn]

            if topic_arn || target_arn
              arn = topic_arn || target_arn
              return arn.split(':')[-1]
            end

            phone_number = context.params[:phone_number]
            return 'phone_number' if phone_number

            queue_url = context.params[:queue_url]
            return queue_url.split('/')[-1] if queue_url

            'unknown'
          end

          def span_name(context, client_method)
            case client_method
            when SQS_SEND_MESSAGE, SQS_SEND_MESSAGE_BATCH, SNS_PUBLISH
              "#{client_method}.#{queue_name(context)}.Publish"
            when SQS_RECEIVE_MESSAGE
              "#{client_method}.#{queue_name(context)}.Receive"
            else
              client_method
            end
          end

          def legacy_span_name(context, client_method)
            case client_method
            when SQS_SEND_MESSAGE, SQS_SEND_MESSAGE_BATCH, SNS_PUBLISH
              "#{MessagingHelper.queue_name(context)} publish"
            when SQS_RECEIVE_MESSAGE
              "#{MessagingHelper.queue_name(context)} receive"
            else
              client_method
            end
          end

          def apply_span_attributes(context, attrs, client_method, service_id)
            case service_id
            when 'SQS'
              apply_sqs_attributes(attrs, context, client_method)
            when 'SNS'
              apply_sns_attributes(attrs, context, client_method)
            end
          end

          def span_kind(client_method)
            case client_method
            when SQS_SEND_MESSAGE, SQS_SEND_MESSAGE_BATCH, SNS_PUBLISH
              OpenTelemetry::Trace::SpanKind::PRODUCER
            when SQS_RECEIVE_MESSAGE
              OpenTelemetry::Trace::SpanKind::CONSUMER
            else
              OpenTelemetry::Trace::SpanKind::CLIENT
            end
          end

          def inject_context_if_supported(context, client_method, service_id)
            if HandlerHelper.instrumentation_config[:inject_messaging_context] &&
               SUPPORTED_SERVICES.include?(service_id)
              inject_context(context, client_method)
            end
          end

          def inject_context(context, client_method)
            return unless SEND_MESSAGE_CLIENT_METHODS.include?(client_method)

            if client_method == SQS_SEND_MESSAGE_BATCH
              context.params[:entries].each do |entry|
                entry[:message_attributes] ||= {}
                OpenTelemetry.propagation.inject(entry[:message_attributes], setter: MessageAttributeSetter)
              end
            else
              context.params[:message_attributes] ||= {}
              OpenTelemetry.propagation.inject(context.params[:message_attributes], setter: MessageAttributeSetter)
            end
          end

          private

          def apply_sqs_attributes(attributes, context, client_method)
            attributes[SemanticConventions::Trace::MESSAGING_SYSTEM] = 'aws.sqs'
            attributes[SemanticConventions::Trace::MESSAGING_DESTINATION_KIND] = 'queue'
            attributes[SemanticConventions::Trace::MESSAGING_DESTINATION] = queue_name(context)
            attributes[SemanticConventions::Trace::MESSAGING_URL] = context.params[:queue_url] if context.params[:queue_url]
            attributes[SemanticConventions::Trace::MESSAGING_OPERATION] = 'receive' if client_method == SQS_RECEIVE_MESSAGE
          end

          def apply_sns_attributes(attributes, context, client_method)
            attributes[SemanticConventions::Trace::MESSAGING_SYSTEM] = 'aws.sns'
            return unless client_method == SNS_PUBLISH

            attributes[SemanticConventions::Trace::MESSAGING_DESTINATION_KIND] = 'topic'
            attributes[SemanticConventions::Trace::MESSAGING_DESTINATION] = queue_name(context)
          end
        end
      end
    end
  end
end
