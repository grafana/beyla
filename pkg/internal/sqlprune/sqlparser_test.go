package sqlprune

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var tableOptional = map[string]bool{
	"SET":      true,
	"SHOW":     true,
	"USE":      true,
	"BEGIN":    true,
	"START":    true,
	"COMMIT":   true,
	"ROLLBACK": true,
}

func RunOneSQLTest(t *testing.T, query string) {
	operation, table := SQLParseOperationAndTable(query)

	if query == "" {
		// Odd case of empty string
		assert.Empty(t, operation, "Expected empty operation, query: %s", query)
		assert.Empty(t, table, "Expected empty operation, query: %s", query)
		return
	}

	if operation == "" {
		// One exception case here:
		if query == "desc foobar" {
			return
		}
		assert.Empty(t, table, "Two errors: operation is empty, but table name (%s) is not.  query: %s", table, query)
		assert.NotEmpty(t, operation, "DB operation not found on query string: %s", query)
		return
	}
	t.Logf("Op/tab: %-20s Query: %s\n", operation+" "+table, query)
	if !tableOptional[operation] {
		// One odd exception case, table can't start with number:
		if query != "select 1" {
			assert.NotEqualValues(t, "", table, "Table was not optional for operator %s.  Query string: %s", operation, query)
		}
	}
}

func TestSQLparser(t *testing.T) {
	for _, sql := range validSQL {
		RunOneSQLTest(t, sql.input)
	}
	RunOneSQLTest(t, "")
}
