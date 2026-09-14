# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry/resource/detector/aws/ec2'
require 'opentelemetry/resource/detector/aws/ecs'
require 'opentelemetry/resource/detector/aws/lambda'
require 'opentelemetry/resource/detector/aws/eks'

module OpenTelemetry
  module Resource
    module Detector
      # AWS contains detect class method for determining AWS environment resource attributes
      module AWS
        extend self

        RESOURCE = OpenTelemetry::SDK::Resources::Resource

        # Get resources from specified AWS resource detectors
        #
        # @param detectors [Array<Symbol>] List of detectors to use (e.g., :ec2)
        # @return [OpenTelemetry::SDK::Resources::Resource] The detected AWS resources
        def detect(detectors = [])
          return RESOURCE.create({}) if detectors.empty?

          resources = detectors.map do |detector|
            case detector
            when :ec2
              EC2.detect
            when :ecs
              ECS.detect
            when :eks
              EKS.detect
            when :lambda
              Lambda.detect
            else
              OpenTelemetry.logger.warn("Unknown AWS resource detector: #{detector}")
              OpenTelemetry::SDK::Resources::Resource.create({})
            end
          end

          # Merge all resources into a single resource
          resources.reduce(OpenTelemetry::SDK::Resources::Resource.create({})) do |merged, resource|
            merged.merge(resource)
          end
        end
      end
    end
  end
end
