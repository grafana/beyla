# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Resource
    module Detector
      # Container contains detect class method for determining container resource attributes
      module Container
        extend self

        UUID_PATTERN = '[0-9a-f]{8}[-_]?[0-9a-f]{4}[-_]?[0-9a-f]{4}[-_]?[0-9a-f]{4}[-_]?[0-9a-f]{12}'
        CONTAINER_PATTERN = '[0-9a-f]{64}'
        CONTAINER_REGEX = /(?<container>#{UUID_PATTERN}|#{CONTAINER_PATTERN})(?:.scope)?$/
        CGROUP_V1_PATH = '/proc/self/cgroup'
        CGROUP_V2_PATH = '/proc/self/mountinfo'

        # Detects container attributes and creates a {OpenTelemetry::SDK::Resources::Resource} with the specified attributes.
        # If no container attributes could be determined an empty resource is returned
        #
        # @return [OpenTelemetry::SDK::Resources::Resource]
        def detect
          id = container_id
          resource_attributes = {}

          resource_attributes[OpenTelemetry::SemanticConventions::Resource::CONTAINER_ID] = id unless id.nil?
          resource_attributes.delete_if { |_key, value| value.nil? || value.empty? }
          OpenTelemetry::SDK::Resources::Resource.create(resource_attributes)
        end

        private

        # Returns the container.id if it can be determined from cgroup
        # or nil if container.id could not be determined
        #
        # @return [String] container.id
        #   May be nil.
        def container_id
          [CGROUP_V2_PATH, CGROUP_V1_PATH].each do |cgroup|
            unless File.readable?(cgroup)
              OpenTelemetry.handle_error(message: "Container resource detector - #{cgroup} could not be read.")
              next
            end

            File.readlines(cgroup, chomp: true).each do |line|
              next if cgroup == CGROUP_V2_PATH && !(line.include?('/docker/containers/') || line.include?('/containers/overlay-containers/'))

              parts = line.split('/')
              parts.shift

              parts.each do |part|
                return part if part.match?(CONTAINER_REGEX)
              end
            end
          end

          nil
        end
      end
    end
  end
end
