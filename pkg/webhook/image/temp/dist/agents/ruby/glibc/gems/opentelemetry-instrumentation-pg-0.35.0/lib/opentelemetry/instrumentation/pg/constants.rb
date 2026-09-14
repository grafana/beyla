# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module PG
      module Constants
        # A list of SQL commands, from: https://www.postgresql.org/docs/current/sql-commands.html
        # Commands are truncated to their first word, and all duplicates
        # are removed, This favors brevity and low-cardinality over descriptiveness.
        SQL_COMMANDS = %w[
          ABORT
          ALTER
          ANALYZE
          BEGIN
          CALL
          CHECKPOINT
          CLOSE
          CLUSTER
          COMMENT
          COMMIT
          COPY
          CREATE
          DEALLOCATE
          DECLARE
          DELETE
          DISCARD
          DO
          DROP
          END
          EXECUTE
          EXPLAIN
          FETCH
          GRANT
          IMPORT
          INSERT
          LISTEN
          LOAD
          LOCK
          MERGE
          MOVE
          NOTIFY
          PREPARE
          REASSIGN
          REFRESH
          REINDEX
          RELEASE
          RESET
          REVOKE
          ROLLBACK
          SAVEPOINT
          SECURITY
          SELECT
          SET
          SHOW
          START
          TRUNCATE
          UNLISTEN
          UPDATE
          VACUUM
          VALUES
        ].freeze

        # These are all alike in that they will have a SQL statement as the first parameter.
        # That statement may possibly be parameterized, but we can still use it - the
        # obfuscation code will just transform $1 -> $? in that case (which is fine enough).
        EXEC_ISH_METHODS = %i[
          exec
          query
          sync_exec
          async_exec
          exec_params
          async_exec_params
          sync_exec_params
        ].freeze

        # The following methods all take a statement name as the first
        # parameter, and a SQL statement as the second - and possibly
        # further parameters after that. We can trace them all alike.
        PREPARE_ISH_METHODS = %i[
          prepare
          async_prepare
          sync_prepare
        ].freeze

        # The following methods take a prepared statement name as their first
        # parameter - everything after that is either potentially quite sensitive
        # (an array of bind params) or not useful to us. We trace them all alike.
        EXEC_PREPARED_ISH_METHODS = %i[
          exec_prepared
          async_exec_prepared
          sync_exec_prepared
        ].freeze

        CONNECTION_METHODS = %i[
          connect
          open
          async_connect
        ].freeze
      end
    end
  end
end
