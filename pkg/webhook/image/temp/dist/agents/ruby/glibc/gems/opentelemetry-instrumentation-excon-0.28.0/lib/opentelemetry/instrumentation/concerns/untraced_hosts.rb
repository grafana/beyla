# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Concerns
      # The untraced hosts concerns allows instrumentation to skip traces on hostnames in an exclusion list.
      # If the current OpenTelemetry context is untraced, all hosts will be treated as untraced.
      # When included in a class that extends OpenTelemetry::Instrumentation::Base, this module defines an option named :untraced_hosts.
      module UntracedHosts
        def self.included(klass)
          klass.instance_eval do
            # untraced_hosts: if a request's address matches any of the `String`
            #   or `Regexp` in this array, the instrumentation will not record a
            #   `kind = :client` representing the request and will not propagate
            #   context in the request.
            option :untraced_hosts, default: [], validate: :array
          end
        end

        # Checks whether the given host should be treated as untraced.
        # If the current OpenTelemetry context is untraced, all hosts will be treated as untraced.
        # The given host must be a String.
        def untraced?(host)
          OpenTelemetry::Common::Utilities.untraced? || untraced_host?(host)
        end

        private

        def untraced_host?(host)
          config[:untraced_hosts].any? do |rule|
            rule.is_a?(Regexp) ? rule.match?(host) : rule == host
          end
        end
      end
    end
  end
end
