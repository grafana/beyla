package sqlprune

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xwb1989/sqlparser"
)

var tableRequired = map[string]bool{
	"DELETE": true,
	"INSERT": true,
	"UPDATE": true,
}

func queryIsNotParsable(query string) bool {
	_, err := sqlparser.Parse(query)
	return err != nil
}

func RunOneSQLTest(t *testing.T, query string) {
	setGlobalTestingT(t)
	operation, table := SQLParseOperationAndTable(query)

	if query == "" {
		// Odd case of empty string
		assert.Empty(t, operation, "Expected empty operation, query: %s", query)
		assert.Empty(t, table, "Expected empty operation, query: %s", query)
		return
	}

	t.Logf("Op/tab: %-20s Query: %s\n", operation+" "+table, query)
	if queryIsNotParsable(query) {
		t.Logf("                                    Above query did not parse successfully with library, skipping checks on output")
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
	if tableRequired[operation] {
		assert.NotEqualValues(t, "", table, "Table was required for operator %s.  Query string: %s", operation, query)
	}
}

func TestSQLParser(t *testing.T) {
	for _, sql := range validSQL {
		RunOneSQLTest(t, sql.input)
	}
	for _, sql := range parameterizedValidSQL {
		RunOneSQLTest(t, sql.input)
	}
	for _, queryString := range otalJavaSqlQueries {
		RunOneSQLTest(t, queryString)
	}
	RunOneSQLTest(t, "")
}
