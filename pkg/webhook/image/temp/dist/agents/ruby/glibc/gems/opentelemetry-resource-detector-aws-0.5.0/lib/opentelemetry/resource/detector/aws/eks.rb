# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'net/http'
require 'json'
require 'openssl'
require 'uri'
require 'opentelemetry/common'
require 'opentelemetry/semantic_conventions/resource'

module OpenTelemetry
  module Resource
    module Detector
      module AWS
        # EKS contains detect class method for determining EKS resource attributes
        module EKS
          extend self

          # Container ID length from cgroup file
          CONTAINER_ID_LENGTH = 64

          # HTTP request timeout in seconds
          HTTP_TIMEOUT = 5

          # Kubernetes token and certificate paths
          TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'
          CERT_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'

          # Kubernetes API paths
          AWS_AUTH_PATH = '/api/v1/namespaces/kube-system/configmaps/aws-auth'
          CLUSTER_INFO_PATH = '/api/v1/namespaces/amazon-cloudwatch/configmaps/cluster-info'

          # Create a constant for resource semantic conventions
          RESOURCE = OpenTelemetry::SemanticConventions::Resource

          def detect
            # Return empty resource if not running on K8s
            return OpenTelemetry::SDK::Resources::Resource.create({}) unless k8s?

            resource_attributes = {}

            begin
              # Get K8s credentials
              cred_value = k8s_cred_value

              # Verify this is an EKS cluster
              unless eks?(cred_value)
                OpenTelemetry.logger.debug('Could not confirm process is running on EKS')
                return OpenTelemetry::SDK::Resources::Resource.create({})
              end

              # Get cluster name and container ID
              cluster_name_val = cluster_name(cred_value)
              container_id_val = container_id

              if container_id_val.empty? && cluster_name_val.empty?
                OpenTelemetry.logger.debug('Neither cluster name nor container ID found on EKS process')
                return OpenTelemetry::SDK::Resources::Resource.create({})
              end

              # Set resource attributes
              resource_attributes[RESOURCE::CLOUD_PROVIDER] = 'aws'
              resource_attributes[RESOURCE::CLOUD_PLATFORM] = 'aws_eks'
              resource_attributes[RESOURCE::K8S_CLUSTER_NAME] = cluster_name_val unless cluster_name_val.empty?
              resource_attributes[RESOURCE::CONTAINER_ID] = container_id_val unless container_id_val.empty?
            rescue StandardError => e
              OpenTelemetry.logger.debug("EKS resource detection failed: #{e.message}")
              return OpenTelemetry::SDK::Resources::Resource.create({})
            end

            resource_attributes.delete_if { |_key, value| value.nil? || value.empty? }
            OpenTelemetry::SDK::Resources::Resource.create(resource_attributes)
          end

          private

          # Check if running on K8s
          #
          # @return [Boolean] true if running on K8s
          def k8s?
            File.exist?(TOKEN_PATH) && File.exist?(CERT_PATH)
          end

          # Get K8s token
          #
          # @return [String] K8s token
          # @raise [StandardError] if token could not be read
          def k8s_cred_value
            token = File.read(TOKEN_PATH).strip
            "Bearer #{token}"
          rescue StandardError => e
            OpenTelemetry.logger.debug("Failed to get k8s token: #{e.message}")
            raise e
          end

          # Check if running on EKS
          #
          # @param cred_value [String] K8s credentials
          # @return [Boolean] true if running on EKS
          def eks?(cred_value)
            # Just try to access the aws-auth configmap
            # If it exists and we can access it, we're on EKS
            aws_http_request(AWS_AUTH_PATH, cred_value)
            true
          rescue StandardError
            false
          end

          # Get EKS cluster name
          #
          # @param cred_value [String] K8s credentials
          # @return [String] Cluster name or empty string if not found
          def cluster_name(cred_value)
            begin
              response = aws_http_request(CLUSTER_INFO_PATH, cred_value)
              cluster_info = JSON.parse(response)
              return cluster_info['data']['cluster.name'] if cluster_info['data'] && cluster_info['data']['cluster.name']
            rescue StandardError => e
              OpenTelemetry.logger.debug("Cannot get cluster name on EKS: #{e.message}")
            end
            ''
          end

          # Get container ID from cgroup file
          #
          # @return [String] Container ID or empty string if not found
          def container_id
            begin
              File.open('/proc/self/cgroup', 'r') do |file|
                file.each_line do |line|
                  line = line.strip
                  # Look for container ID (64 chars) at the end of the line
                  return line[-CONTAINER_ID_LENGTH..-1] if line.length > CONTAINER_ID_LENGTH
                end
              end
            rescue StandardError => e
              OpenTelemetry.logger.debug("Failed to get container ID on EKS: #{e.message}")
            end
            ''
          end

          # Make HTTP GET request to K8s API
          #
          # @param path [String] API path
          # @param cred_value [String] Authorization header value
          # @return [String] Response body
          # @raise [StandardError] if request fails
          def aws_http_request(path, cred_value)
            uri = URI.parse("https://kubernetes.default.svc#{path}")
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = true
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
            http.ca_file = CERT_PATH
            http.open_timeout = HTTP_TIMEOUT
            http.read_timeout = HTTP_TIMEOUT

            request = Net::HTTP::Get.new(uri)
            request['Authorization'] = cred_value

            OpenTelemetry::Common::Utilities.untraced do
              response = http.request(request)
              raise "HTTP request failed with status #{response.code}" unless response.is_a?(Net::HTTPSuccess)

              response.body
            end
          end
        end
      end
    end
  end
end
