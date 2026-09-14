# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0module OpenTelemetry
require 'opentelemetry-common'

module OpenTelemetry
  module Helpers
    # This module contains helpers for MySQL instrumentation libraries, like mysql2 and
    # trilogy. It is intended for use by instrumentation developers and not to
    # be called directly by an application.
    #
    # To use this in your instrumentation, the `Instrumentation` class for
    # your gem must contain configuration options for:
    #  * `:span_name`
    #  Example:
    #  `option :span_name, default: :statement_type, validate: %I[statement_type db_name db_operation_and_name]`
    #
    # @api public
    module MySQL
      module_function

      QUERY_NAMES = [
        'set names',
        'select',
        'insert',
        'update',
        'delete',
        'begin',
        'commit',
        'rollback',
        'savepoint',
        'release savepoint',
        'explain',
        'drop database',
        'drop table',
        'create database',
        'create table'
      ].freeze

      # Ignore query names that might appear in comments prepended to the
      # statement.
      PREPENDED_COMMENTS_REGEX = %r{(?:\/\*.*?\*\/)}m
      QUERY_NAME_REGEX = Regexp.new("^\s*(?:#{PREPENDED_COMMENTS_REGEX})?\s*\\b(#{QUERY_NAMES.join('|')})\\b", Regexp::IGNORECASE)

      # This is a span naming utility intended for use in MySQL database
      # adapter instrumentation.
      #
      # @param sql [String] The SQL statement for the span.
      # @param operation [String] The database operation.
      # @param database_name [String] The name of the database.
      # @param config [Hash] The user's configuration for the database adapter.
      #  Desired keys:
      #    * `:span_name` => A symbol describing the type of name desired. Expected options are `:statement_type`, `:db_name`, and `:db_operation_and_name`. A nil or unknown `:span_name` will return 'mysql' as the span name
      # @return [String] The span name.
      # @api public
      def database_span_name(sql, operation, database_name, config)
        case config[:span_name]
        when :statement_type
          extract_statement_type(sql)
        when :db_name
          database_name
        when :db_operation_and_name
          db_operation_and_name(operation, database_name)
        end || 'mysql'
      end

      # @api private
      def extract_statement_type(sql)
        return unless sql

        sql = OpenTelemetry::Common::Utilities.utf8_encode(sql, binary: true) unless sql.encoding == ::Encoding::UTF_8 && sql.valid_encoding?

        QUERY_NAME_REGEX.match(sql) { |match| match[1].downcase }
      rescue StandardError => e
        OpenTelemetry.handle_error(message: 'Error extracting SQL statement type', exception: e)
        nil
      end

      # @api private
      def db_operation_and_name(operation, database_name)
        if operation && database_name
          "#{operation} #{database_name}"
        elsif operation
          operation
        elsif database_name
          database_name
        end
      end
    end
  end
end
