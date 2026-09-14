# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'net/http'

module OpenTelemetry
  module Resource
    module Detector
      # Azure contains detect class method for determining Azure environment resource attributes
      module Azure
        extend self

        AZURE_METADATA_URI = 'http://169.254.169.254/metadata/instance/compute?api-version=2019-08-15'

        def detect
          metadata = azure_metadata
          resource_attributes = {}

          unless metadata.nil?
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::CLOUD_PROVIDER] = 'azure'
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::CLOUD_ACCOUNT_ID] = metadata['subscriptionId']
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::CLOUD_PLATFORM] = cloud_platform(metadata['provider'])
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::CLOUD_REGION] = metadata['location']
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::CLOUD_AVAILABILITY_ZONE] = metadata['zone']

            resource_attributes[OpenTelemetry::SemanticConventions::Resource::HOST_ID] = metadata['vmId']
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::HOST_IMAGE_ID] = metadata.dig('storageProfile', 'imageReference', 'id')
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::HOST_TYPE] = metadata['vmSize']
            resource_attributes[OpenTelemetry::SemanticConventions::Resource::HOST_NAME] = metadata['name']
          end

          resource_attributes.delete_if { |_key, value| value.nil? || value.empty? }
          OpenTelemetry::SDK::Resources::Resource.create(resource_attributes)
        end

        private

        def azure_metadata
          uri = URI(AZURE_METADATA_URI)

          req = Net::HTTP::Get.new(uri)
          req['Metadata'] = 'true'

          response = Net::HTTP.start(uri.hostname, uri.port, open_timeout: 2) do |http|
            http.request(req)
          end

          return unless response.code == '200'

          JSON.parse(response.body)
        rescue Errno::EHOSTDOWN, Net::OpenTimeout, SocketError
          nil
        end

        def cloud_platform(metadata)
          case metadata
          when 'Microsoft.Compute'
            'azure_vm'
          else
            ''
          end
        end
      end
    end
  end
end
