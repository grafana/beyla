# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'net/http'
require 'json'
require 'opentelemetry/common'
require 'opentelemetry/semantic_conventions/resource'

module OpenTelemetry
  module Resource
    module Detector
      module AWS
        # EC2 contains detect class method for determining EC2 resource attributes
        module EC2
          extend self

          # EC2 metadata service endpoints and constants
          EC2_METADATA_HOST = '169.254.169.254'
          TOKEN_ENDPOINT = '/latest/api/token'
          IDENTITY_DOCUMENT_ENDPOINT = '/latest/dynamic/instance-identity/document'
          HOSTNAME_ENDPOINT = '/latest/meta-data/hostname'

          TOKEN_HEADER = 'X-aws-ec2-metadata-token'
          TOKEN_TTL_HEADER = 'X-aws-ec2-metadata-token-ttl-seconds'
          TOKEN_TTL_VALUE = '60'

          # Timeout in seconds for HTTP requests
          HTTP_TIMEOUT = 1

          # Create a constant for resource semantic conventions
          RESOURCE = OpenTelemetry::SemanticConventions::Resource

          def detect
            # Implementation for EC2 detection supporting both IMDSv1 and IMDSv2
            resource_attributes = {}

            begin
              # Attempt to get IMDSv2 token - this will fail if IMDSv2 is not supported
              # but we'll still try IMDSv1 in that case
              token = fetch_token

              # Get instance identity document which contains most metadata
              # Will try with token (IMDSv2) or without token (IMDSv1)
              identity = fetch_identity_document(token) || {}
              return OpenTelemetry::SDK::Resources::Resource.create({}) if identity.empty?

              hostname = fetch_hostname(token)

              # Set resource attributes from the identity document
              resource_attributes[RESOURCE::CLOUD_PROVIDER] = 'aws'
              resource_attributes[RESOURCE::CLOUD_PLATFORM] = 'aws_ec2'
              resource_attributes[RESOURCE::CLOUD_ACCOUNT_ID] = identity['accountId']
              resource_attributes[RESOURCE::CLOUD_REGION] = identity['region']
              resource_attributes[RESOURCE::CLOUD_AVAILABILITY_ZONE] = identity['availabilityZone']

              resource_attributes[RESOURCE::HOST_ID] = identity['instanceId']
              resource_attributes[RESOURCE::HOST_TYPE] = identity['instanceType']
              resource_attributes[RESOURCE::HOST_NAME] = hostname
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e, message: 'EC2 resource detection failed')
              return OpenTelemetry::SDK::Resources::Resource.create({})
            end

            # Filter out nil or empty values
            resource_attributes.delete_if { |_key, value| value.nil? || value.empty? }
            OpenTelemetry::SDK::Resources::Resource.create(resource_attributes)
          end

          private

          # Fetches an IMDSv2 token from the EC2 metadata service
          #
          # @return [String, nil] The token or nil if the request failed
          def fetch_token
            uri = URI.parse("http://#{EC2_METADATA_HOST}#{TOKEN_ENDPOINT}")
            request = Net::HTTP::Put.new(uri)
            request[TOKEN_TTL_HEADER] = TOKEN_TTL_VALUE

            response = make_request(uri, request)
            return nil unless response.is_a?(Net::HTTPSuccess)

            response.body
          end

          # Fetches the instance identity document which contains EC2 instance metadata
          #
          # @param token [String, nil] IMDSv2 token (optional for IMDSv1)
          # @return [Hash, nil] Parsed identity document or nil if the request failed
          def fetch_identity_document(token)
            uri = URI.parse("http://#{EC2_METADATA_HOST}#{IDENTITY_DOCUMENT_ENDPOINT}")
            request = Net::HTTP::Get.new(uri)
            request[TOKEN_HEADER] = token if token

            response = make_request(uri, request)
            return nil unless response.is_a?(Net::HTTPSuccess)

            begin
              JSON.parse(response.body)
            rescue JSON::ParserError
              nil
            end
          end

          # Fetches the EC2 instance hostname
          #
          # @param token [String, nil] IMDSv2 token (optional for IMDSv1)
          # @return [String, nil] The hostname or nil if the request failed
          def fetch_hostname(token)
            uri = URI.parse("http://#{EC2_METADATA_HOST}#{HOSTNAME_ENDPOINT}")
            request = Net::HTTP::Get.new(uri)
            request[TOKEN_HEADER] = token if token

            response = make_request(uri, request)
            return nil unless response.is_a?(Net::HTTPSuccess)

            response.body
          end

          # Makes an HTTP request with timeout handling
          #
          # @param uri [URI] The request URI
          # @param request [Net::HTTP::Request] The request to perform
          # @return [Net::HTTPResponse, nil] The response or nil if the request failed
          def make_request(uri, request)
            http = Net::HTTP.new(uri.host, uri.port)
            http.open_timeout = HTTP_TIMEOUT
            http.read_timeout = HTTP_TIMEOUT

            begin
              OpenTelemetry::Common::Utilities.untraced do
                http.request(request)
              end
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e, message: 'EC2 metadata service request failed')
              nil
            end
          end
        end
      end
    end
  end
end
