# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/semantic_conventions/resource'

module OpenTelemetry
  module Resource
    module Detector
      module AWS
        # Lambda contains detect class method for determining Lambda resource attributes
        module Lambda
          extend self

          # Create a constant for resource semantic conventions
          RESOURCE = OpenTelemetry::SemanticConventions::Resource

          def detect
            # Return empty resource if not running on Lambda
            return OpenTelemetry::SDK::Resources::Resource.create({}) unless lambda_environment?

            resource_attributes = {}

            begin
              # Set Lambda-specific attributes from environment variables
              resource_attributes[RESOURCE::CLOUD_PROVIDER] = 'aws'
              resource_attributes[RESOURCE::CLOUD_PLATFORM] = 'aws_lambda'
              resource_attributes[RESOURCE::CLOUD_REGION] = ENV.fetch('AWS_REGION', nil)
              resource_attributes[RESOURCE::FAAS_NAME] = ENV.fetch('AWS_LAMBDA_FUNCTION_NAME', nil)
              resource_attributes[RESOURCE::FAAS_VERSION] = ENV.fetch('AWS_LAMBDA_FUNCTION_VERSION', nil)
              resource_attributes[RESOURCE::FAAS_INSTANCE] = ENV.fetch('AWS_LAMBDA_LOG_STREAM_NAME', nil)

              # Convert memory size to integer
              resource_attributes[RESOURCE::FAAS_MAX_MEMORY] = ENV['AWS_LAMBDA_FUNCTION_MEMORY_SIZE'].to_i if ENV['AWS_LAMBDA_FUNCTION_MEMORY_SIZE']
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e, message: 'Lambda resource detection failed')
              return OpenTelemetry::SDK::Resources::Resource.create({})
            end

            # Filter out nil or empty values
            # Note: we need to handle integers differently since they don't respond to empty?
            resource_attributes.delete_if do |_key, value|
              value.nil? || (value.respond_to?(:empty?) && value.empty?)
            end

            OpenTelemetry::SDK::Resources::Resource.create(resource_attributes)
          end

          private

          # Determines if the current environment is AWS Lambda
          #
          # @return [Boolean] true if running on AWS Lambda
          def lambda_environment?
            # Check for Lambda-specific environment variables
            !ENV['AWS_LAMBDA_FUNCTION_NAME'].nil? &&
              !ENV['AWS_LAMBDA_FUNCTION_VERSION'].nil? &&
              !ENV['AWS_LAMBDA_LOG_STREAM_NAME'].nil?
          end
        end
      end
    end
  end
end
