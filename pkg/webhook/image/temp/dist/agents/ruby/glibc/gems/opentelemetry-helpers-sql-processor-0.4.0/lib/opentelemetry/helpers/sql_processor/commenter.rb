# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'cgi'

module OpenTelemetry
  module Helpers
    module SqlProcessor
      # SqlCommenter provides SQL comment-based trace context propagation
      # according to the SQL Commenter specification.
      #
      # This module implements a propagator interface compatible with Vitess,
      # allowing it to be used as a drop-in replacement.
      #
      # @api public
      module SqlCommenter
        extend self

        # SqlQuerySetter is responsible for formatting trace context as SQL comments
        # and appending them to SQL queries according to the SQL Commenter specification.
        #
        # Format: /*key='value',key2='value2'*/
        # Values are URL-encoded per the SQL Commenter spec
        module SqlQuerySetter
          extend self

          # Appends trace context as a SQL comment to the carrier (SQL query string)
          #
          # @param carrier [String] The SQL query string to modify
          # @param headers [Hash] Hash of trace context headers (e.g., {'traceparent' => '00-...'})
          def set(carrier, headers)
            return if headers.empty?
            return if carrier.frozen?

            # Convert headers hash to SQL commenter format
            # Format: /*key1='value1',key2='value2'*/
            comment_parts = headers.map do |key, value|
              # URL encode values as per SQL Commenter spec (using URI component encoding)
              encoded_value = CGI.escapeURIComponent(value.to_s)
              "#{key}='#{encoded_value}'"
            end

            # Append to end of query (spec recommendation)
            carrier << " /*#{comment_parts.join(',')}*/"
          end
        end

        # SqlQueryPropagator propagates trace context using SQL comments
        # according to the SQL Commenter specification.
        #
        # This propagator implements the same interface as the Vitess propagator
        # and can be used as a drop-in replacement.
        #
        # @example
        #   propagator = OpenTelemetry::Helpers::SqlProcessor::SqlCommenter.sql_query_propagator
        #   sql = "SELECT * FROM users"
        #   propagator.inject(sql, context: current_context)
        #   # => "SELECT * FROM users /*traceparent='00-...',tracestate='...'*/"
        module SqlQueryPropagator
          extend self

          # Injects trace context into a SQL query as a comment
          #
          # @param carrier [String] The SQL query string to inject context into
          # @param context [optional, Context] The context to inject. Defaults to current context.
          # @param setter [optional, #set] The setter to use for appending the comment.
          #   Defaults to SqlQuerySetter.
          # @return [nil]
          def inject(carrier, context: OpenTelemetry::Context.current, setter: SqlQuerySetter)
            # Use the global propagator to extract headers into a hash
            headers = {}
            OpenTelemetry.propagation.inject(headers, context: context)

            # Pass the headers to our SQL comment setter
            setter.set(carrier, headers)
            nil
          end
        end

        # Returns the SqlQueryPropagator module for stateless propagation
        #
        # @return [Module] The SqlQueryPropagator module
        def sql_query_propagator
          SqlQueryPropagator
        end
      end
    end
  end
end
