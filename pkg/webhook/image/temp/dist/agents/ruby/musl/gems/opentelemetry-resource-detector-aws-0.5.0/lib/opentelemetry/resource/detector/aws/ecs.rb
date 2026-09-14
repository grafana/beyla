# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'net/http'
require 'json'
require 'socket'
require 'opentelemetry/common'
require 'opentelemetry/semantic_conventions/resource'

module OpenTelemetry
  module Resource
    module Detector
      module AWS
        # ECS contains detect class method for determining the ECS resource attributes
        module ECS
          extend self

          # Container ID length from cgroup file
          CONTAINER_ID_LENGTH = 64

          # HTTP request timeout in seconds
          HTTP_TIMEOUT = 5

          # Create a constant for resource semantic conventions
          RESOURCE = OpenTelemetry::SemanticConventions::Resource

          def detect
            # Return empty resource if not running on ECS
            metadata_uri = ENV.fetch('ECS_CONTAINER_METADATA_URI', nil)
            metadata_uri_v4 = ENV.fetch('ECS_CONTAINER_METADATA_URI_V4', nil)

            return OpenTelemetry::SDK::Resources::Resource.create({}) if metadata_uri.nil? && metadata_uri_v4.nil?

            resource_attributes = {}
            container_id = fetch_container_id

            # Base ECS resource attributes
            resource_attributes[RESOURCE::CLOUD_PROVIDER] = 'aws'
            resource_attributes[RESOURCE::CLOUD_PLATFORM] = 'aws_ecs'
            resource_attributes[RESOURCE::CONTAINER_NAME] = Socket.gethostname
            resource_attributes[RESOURCE::CONTAINER_ID] = container_id unless container_id.empty?

            # If v4 endpoint is not available, return basic resource
            return OpenTelemetry::SDK::Resources::Resource.create(resource_attributes) if metadata_uri_v4.nil?

            begin
              # Fetch container and task metadata
              container_metadata = JSON.parse(http_get(metadata_uri_v4.to_s))
              task_metadata = JSON.parse(http_get("#{metadata_uri_v4}/task"))

              task_arn = task_metadata['TaskARN']
              base_arn = task_arn[0..(task_arn.rindex(':') - 1)]

              cluster = task_metadata['Cluster']
              cluster_arn = cluster.start_with?('arn:') ? cluster : "#{base_arn}:cluster/#{cluster}"

              # Set ECS-specific attributes
              resource_attributes[RESOURCE::AWS_ECS_CONTAINER_ARN] = container_metadata['ContainerARN']
              resource_attributes[RESOURCE::AWS_ECS_CLUSTER_ARN] = cluster_arn
              resource_attributes[RESOURCE::AWS_ECS_LAUNCHTYPE] = task_metadata['LaunchType'].downcase
              resource_attributes[RESOURCE::AWS_ECS_TASK_ARN] = task_arn
              resource_attributes[RESOURCE::AWS_ECS_TASK_FAMILY] = task_metadata['Family']
              resource_attributes[RESOURCE::AWS_ECS_TASK_REVISION] = task_metadata['Revision']

              # Add logging attributes if awslogs is used
              logs_attributes = get_logs_resource(container_metadata)
              resource_attributes.merge!(logs_attributes)
            rescue StandardError => e
              OpenTelemetry.handle_error(exception: e, message: 'ECS resource detection failed')
              return OpenTelemetry::SDK::Resources::Resource.create({})
            end

            # Filter out nil or empty values
            resource_attributes.delete_if { |_key, value| value.nil? || value.empty? }
            OpenTelemetry::SDK::Resources::Resource.create(resource_attributes)
          end

          private

          # Fetches container ID from /proc/self/cgroup file
          #
          # @return [String] The container ID or empty string if not found
          def fetch_container_id
            begin
              File.open('/proc/self/cgroup', 'r') do |file|
                file.each_line do |line|
                  line = line.strip
                  # Look for container ID (64 chars) at the end of the line
                  return line[-CONTAINER_ID_LENGTH..-1] if line.length > CONTAINER_ID_LENGTH
                end
              end
            rescue Errno::ENOENT => e
              OpenTelemetry.handle_error(exception: e, message: 'Failed to get container ID on ECS')
            end

            ''
          end

          # Extracting logging-related resource attributes
          #
          # @param container_metadata [Hash] Container metadata from ECS metadata endpoint
          # @returhn [Hash] Resource attributes for logging configuration
          def get_logs_resource(container_metadata)
            log_attributes = {}

            if container_metadata['LogDriver'] == 'awslogs'
              log_options = container_metadata['LogOptions']

              if log_options
                logs_region = log_options['awslogs-region']
                logs_group_name = log_options['awslogs-group']
                logs_stream_name = log_options['awslogs-stream']

                container_arn = container_metadata['ContainerARN']

                # Parse region from ARN if not specified in log options
                if logs_region.nil? || logs_region.empty?
                  region_match = container_arn.match(/arn:aws:ecs:([^:]+):.*/)
                  logs_region = region_match[1] if region_match
                end

                # Parse account ID from ARN
                account_match = container_arn.match(/arn:aws:ecs:[^:]+:([^:]+):.*/)
                aws_account = account_match[1] if account_match

                logs_group_arn = nil
                logs_stream_arn = nil

                if logs_region && aws_account
                  logs_group_arn = "arn:aws:logs:#{logs_region}:#{aws_account}:log-group:#{logs_group_name}" if logs_group_name

                  logs_stream_arn = "arn:aws:logs:#{logs_region}:#{aws_account}:log-group:#{logs_group_name}:log-stream:#{logs_stream_name}" if logs_stream_name && logs_group_name
                end

                log_attributes[RESOURCE::AWS_LOG_GROUP_NAMES] = [logs_group_name].compact
                log_attributes[RESOURCE::AWS_LOG_GROUP_ARNS] = [logs_group_arn].compact
                log_attributes[RESOURCE::AWS_LOG_STREAM_NAMES] = [logs_stream_name].compact
                log_attributes[RESOURCE::AWS_LOG_STREAM_ARNS] = [logs_stream_arn].compact
              else
                OpenTelemetry.handle_error(message: 'The metadata endpoint v4 has returned \'awslogs\' as \'LogDriver\', but there is no \'LogOptions\' data')
              end
            end

            log_attributes
          end

          # Makes an HTTP GET request to the specified URL
          #
          # @param url [String] The URL to request
          # @return [String] The response body
          def http_get(url)
            uri = URI.parse(url)
            request = Net::HTTP::Get.new(uri)

            http = Net::HTTP.new(uri.host, uri.port)
            http.open_timeout = HTTP_TIMEOUT
            http.read_timeout = HTTP_TIMEOUT

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
