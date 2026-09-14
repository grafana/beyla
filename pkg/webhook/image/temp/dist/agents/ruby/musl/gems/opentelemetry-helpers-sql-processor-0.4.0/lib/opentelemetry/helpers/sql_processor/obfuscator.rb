# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0module OpenTelemetry

require 'opentelemetry-common'

module OpenTelemetry
  module Helpers
    module SqlProcessor
      #
      # This module contains SQL obfuscation behavior to share with
      # instrumentation for specific database adapters.
      # The class uses code from: https://github.com/newrelic/newrelic-ruby-agent/blob/1fca78cc7a087421ad58088d8bea72c0362bc62f/lib/new_relic/agent/database/obfuscation_helpers.rb
      #
      # To use this in your instrumentation, the `Instrumentation` class for
      # your gem must contain configuration options for:
      #  * `:db_statement`
      #    Example:
      #    `option :db_statement, default: :include, validate: %I[omit include obfuscate]`
      #  * `:obfuscation_limit`
      #    Example:
      #    `option :obfuscation_limit, default: 2000, validate: :integer`
      #
      # If you want to add support for a new adapter, update the following
      # constants to include keys for your adapter:
      #  * DIALECT_COMPONENTS
      #  * CLEANUP_REGEX
      # You must also add a new constant that uses `generate_regex` with your
      # adapter's dialect components that is named like
      # `<ADAPTER>_COMPONENTS_REGEX`, such as: `MYSQL_COMPONENTS_REGEX`.
      #
      # @api public
      module Obfuscator
        module_function

        # From: https://github.com/newrelic/newrelic-ruby-agent/blob/1fca78cc7a087421ad58088d8bea72c0362bc62f/lib/new_relic/agent/database/obfuscation_helpers.rb
        COMPONENTS_REGEX_MAP = {
          single_quotes: /'(?:[^']|'')*?(?:\\'.*|'(?!'))/,
          double_quotes: /"(?:[^"]|"")*?(?:\\".*|"(?!"))/,
          dollar_quotes: /(\$(?!\d)[^$]*?\$).*?(?:\1|$)/,
          uuids: /\{?(?:[0-9a-fA-F]\-*){32}\}?/,
          numeric_literals: /-?\b(?:[0-9]+\.)?[0-9]+([eE][+-]?[0-9]+)?\b/,
          boolean_literals: /\b(?:true|false|null)\b/i,
          hexadecimal_literals: /0x[0-9a-fA-F]+/,
          comments: /(?:#|--).*?(?=\r|\n|$)/i,
          multi_line_comments: %r{(?:\/\*.*?\*\/)}m,
          oracle_quoted_strings: /q'\[.*?(?:\]'|$)|q'\{.*?(?:\}'|$)|q'\<.*?(?:\>'|$)|q'\(.*?(?:\)'|$)/
        }.freeze

        DIALECT_COMPONENTS = {
          default: COMPONENTS_REGEX_MAP.keys,
          mysql: %i[single_quotes double_quotes numeric_literals boolean_literals
                    hexadecimal_literals comments multi_line_comments],
          postgres: %i[single_quotes dollar_quotes uuids numeric_literals
                       boolean_literals comments multi_line_comments],
          sqlite: %i[single_quotes numeric_literals boolean_literals hexadecimal_literals
                     comments multi_line_comments],
          oracle: %i[single_quotes oracle_quoted_strings numeric_literals comments
                     multi_line_comments],
          cassandra: %i[single_quotes uuids numeric_literals boolean_literals
                        hexadecimal_literals comments multi_line_comments]
        }.freeze

        PLACEHOLDER = '?'

        # We use these to check whether the query contains any quote characters
        # after obfuscation. If so, that's a good indication that the original
        # query was malformed, and so our obfuscation can't reliably find
        # literals. In such a case, we'll replace the entire query with a
        # placeholder.
        CLEANUP_REGEX = {
          default: %r{'|"|\/\*|\*\/},
          mysql: %r{'|"|\/\*|\*\//},
          postgres: %r{'|\/\*|\*\/|\$(?!\?)/},
          sqlite: %r{'|\/\*|\*\//},
          cassandra: %r{'|\/\*|\*\//},
          oracle: %r{'|\/\*|\*\//}
        }.freeze

        # @api private
        def generate_regex(dialect)
          components = DIALECT_COMPONENTS[dialect]
          Regexp.union(components.map { |component| COMPONENTS_REGEX_MAP[component] })
        end

        DEFAULT_COMPONENTS_REGEX = generate_regex(:default)
        MYSQL_COMPONENTS_REGEX = generate_regex(:mysql)
        POSTGRES_COMPONENTS_REGEX = generate_regex(:postgres)
        SQLITE_COMPONENTS_REGEX = generate_regex(:sqlite)
        CASSANDRA_COMPONENTS_REGEX = generate_regex(:cassandra)
        ORACLE_COMPONENTS_REGEX = generate_regex(:oracle)

        # Internal implementation of SQL obfuscation.
        # Use SqlProcessor.obfuscate_sql for the public API.
        #
        # @api private
        def obfuscate_sql(sql, obfuscation_limit: 2000, adapter: :default)
          return "SQL not obfuscated, query exceeds #{obfuscation_limit} characters" if sql.size > obfuscation_limit

          regex = case adapter
                  when :mysql
                    MYSQL_COMPONENTS_REGEX
                  when :postgres
                    POSTGRES_COMPONENTS_REGEX
                  else
                    DEFAULT_COMPONENTS_REGEX
                  end

          # Original MySQL UTF-8 Encoding Fixes:
          # https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/160
          # https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/345
          sql = OpenTelemetry::Common::Utilities.utf8_encode(sql, binary: true)

          sql = sql.gsub(regex, PLACEHOLDER)
          return 'Failed to obfuscate SQL query - quote characters remained after obfuscation' if CLEANUP_REGEX[adapter].match(sql)

          sql
        rescue StandardError => e
          OpenTelemetry.handle_error(message: 'Failed to obfuscate SQL', exception: e)
        end
      end
    end
  end
end
