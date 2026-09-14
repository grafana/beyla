# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module AwsSdk
      # The MessageAttributeSetter class provides methods for writing tracing information to
      # SNS / SQS messages.
      #
      # @example
      #   OpenTelemetry.propagation.inject(context.params[:message_attributes], setter: MessageAttributeSetter)
      class MessageAttributeSetter
        def self.set(carrier, key, value)
          # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-quotas.html
          if carrier.length < 10
            carrier[key] = { string_value: value, data_type: 'String' }
          else
            OpenTelemetry.logger.warn('aws-sdk instrumentation: cannot set context propagation on SQS/SNS message due to maximum amount of MessageAttributes')
          end
        end
      end

      # The MessageAttributeGetter class provides methods for getting tracing information from SQS message.
      #
      # @example
      #   OpenTelemetry.propagation.extract(message, getter: MessageAttributeGetter)
      class MessageAttributeGetter
        def self.get(carrier, key)
          message_attribute = carrier[key]
          message_attribute[:string_value] if message_attribute && message_attribute[:data_type] == 'String'
        end
      end
    end
  end
end
