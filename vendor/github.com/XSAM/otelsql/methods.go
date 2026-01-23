// Copyright Sam Xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelsql

// Method specifics operation in the database/sql package.
type Method string

// Event specifics events in the database/sql package.
type Event string

const (
	// MethodConnectorConnect is used when driver.Connector.Connect is called to establish a new connection.
	MethodConnectorConnect Method = "sql.connector.connect"
	// MethodConnPing is used with driver.Pinger.Ping to verify database connection is alive.
	MethodConnPing Method = "sql.conn.ping"
	// MethodConnExec is used with driver.ExecerContext.ExecContext for direct query execution through a connection.
	MethodConnExec Method = "sql.conn.exec"
	// MethodConnQuery is used with driver.QueryerContext.QueryContext for executing queries directly through a connection.
	MethodConnQuery Method = "sql.conn.query"
	// MethodConnPrepare is used with driver.ConnPrepareContext.PrepareContext for creating prepared statements.
	MethodConnPrepare Method = "sql.conn.prepare"
	// MethodConnBeginTx is used with driver.ConnBeginTx.BeginTx for starting a new transaction.
	MethodConnBeginTx Method = "sql.conn.begin_tx"
	// MethodConnResetSession is used with driver.SessionResetter.ResetSession to reset connection session state.
	MethodConnResetSession Method = "sql.conn.reset_session"
	// MethodTxCommit is used with driver.Tx.Commit to commit a transaction.
	MethodTxCommit Method = "sql.tx.commit"
	// MethodTxRollback is used with driver.Tx.Rollback to rollback a transaction.
	MethodTxRollback Method = "sql.tx.rollback"
	// MethodStmtExec is used with driver.StmtExecContext.ExecContext to execute a prepared statement.
	MethodStmtExec Method = "sql.stmt.exec"
	// MethodStmtQuery is used with driver.StmtQueryContext.QueryContext to query using a prepared statement.
	MethodStmtQuery Method = "sql.stmt.query"
	// MethodRows is used to track the lifecycle of driver.Rows returned by query operations.
	MethodRows Method = "sql.rows"
)

const (
	// EventRowsNext is triggered during driver.Rows.Next iteration to track each row fetching operation.
	EventRowsNext Event = "sql.rows.next"
)
