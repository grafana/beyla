package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type bindParseResult struct {
	statement    string
	portal       string
	args         []string
	hasErr       bool
	hasASCIIArgs bool
}

type bindTest struct {
	name   string
	bytes  []byte
	isBind bool
	result bindParseResult
}

func TestPostgresBindParsing(t *testing.T) {
	for _, ts := range []bindTest{
		{
			name:   "Valid bind",
			bytes:  []byte{66, 0, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "ecto_1158",
				args:         []string{"recommendationCache"},
				hasErr:       false,
				hasASCIIArgs: true,
			},
		},
		{
			name:   "Less length than needed",
			bytes:  []byte{66, 0, 0, 0, 12, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "ecto_1",
				args:         []string{},
				hasErr:       true,
				hasASCIIArgs: true,
			},
		},
		{
			name:   "Not a bind",
			bytes:  []byte{67, 0, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "Too long",
			bytes:  []byte{66, 100, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "Too short",
			bytes:  []byte{67, 100},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "Empty",
			bytes:  []byte{},
			isBind: false,
			result: bindParseResult{},
		},
		{
			name:   "A bind, but without anything reasonable",
			bytes:  []byte{66, 0, 0, 0, 12},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "",
				args:         []string{},
				hasErr:       true,
				hasASCIIArgs: true,
			},
		},
		{
			name:   "Crazy long argument length",
			bytes:  []byte{66, 0, 0, 0, 52, 0, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 0, 1, 0, 1, 0, 1, 0, 0, 100, 19, 114, 101, 99, 111, 109, 109, 101, 110, 100, 97, 116, 105, 111, 110, 67, 97, 99, 104, 101, 0, 3, 0, 1, 0, 1, 0, 1, 69, 0, 0, 0, 9, 0, 0, 0, 0, 0, 83, 0, 0, 0, 4, 0, 4, 34, 101, 110, 97, 98, 108, 101, 100, 34, 32, 70, 82, 79, 77, 32, 34, 102, 101, 97, 116, 117, 114, 101, 102, 108, 97, 103, 115, 34, 32, 65, 83, 32, 102, 48, 32, 87, 72, 69, 82, 69, 32, 40, 102, 48, 46, 34, 110, 97, 109, 101, 34, 32, 61, 32, 36, 49, 41, 0, 0, 1, 0, 0, 0, 25, 68, 0, 0, 0, 15, 83, 101, 99, 116, 111, 95, 49, 49, 53, 56, 0, 72, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			isBind: true,
			result: bindParseResult{
				statement:    "",
				portal:       "ecto_1158",
				args:         []string{"recommendationCache"},
				hasErr:       false,
				hasASCIIArgs: false,
			},
		},
	} {
		t.Run(ts.name, func(t *testing.T) {
			ok := isPostgresBindCommand(ts.bytes)
			assert.Equal(t, ts.isBind, ok)
			if ok {
				statement, portal, args, err := parsePostgresBindCommand(ts.bytes)
				if ts.result.hasErr {
					assert.True(t, err != nil)
				} else {
					assert.True(t, err == nil)
				}
				assert.Equal(t, ts.result.statement, statement)
				assert.Equal(t, ts.result.portal, portal)
				if ts.result.hasASCIIArgs {
					assert.Equal(t, ts.result.args, args)
				} else {
					for _, arg := range args {
						assert.False(t, isASCII(arg))
					}
				}
			}
		})
	}
}

type qSQLTest struct {
	name  string
	bytes []byte
	op    string
	table string
	sql   string
}

func TestPostgresQueryParsing(t *testing.T) {
	for _, ts := range []qSQLTest{
		{
			name:  "Query prepared statement",
			bytes: []byte{81, 0, 0, 0, 28, 101, 120, 101, 99, 117, 116, 101, 32, 109, 121, 95, 99, 111, 110, 116, 97, 99, 116, 115, 32, 40, 49, 41, 0, 69, 76, 69, 67, 84, 32, 42, 32, 102, 114, 111, 109, 32, 97, 99, 99, 111, 117, 110, 116, 105, 110, 103, 46, 99, 111, 110, 116, 97, 99, 116, 115, 32, 87, 72, 69, 82, 69, 32, 105, 100, 32, 61, 32, 36, 49, 0, 53, 90, 51, 106, 119, 55, 54, 111, 100, 85, 115, 57, 78, 75, 72, 73, 76, 119, 120, 104, 108, 81, 118, 50, 98, 122, 70, 72, 111, 73, 70, 48, 61},
			op:    "execute",
			table: "my_contacts",
			sql:   "execute my_contacts (1)",
		},
		{
			name:  "Query prepared statement bad len",
			bytes: []byte{81, 0, 0, 0, 7, 101, 120, 101, 99, 117, 116, 101, 32, 109, 121, 95, 99, 111, 110, 116, 97, 99, 116, 115, 32, 40, 49, 41, 0, 69, 76, 69, 67, 84, 32, 42, 32, 102, 114, 111, 109, 32, 97, 99, 99, 111, 117, 110, 116, 105, 110, 103, 46, 99, 111, 110, 116, 97, 99, 116, 115, 32, 87, 72, 69, 82, 69, 32, 105, 100, 32, 61, 32, 36, 49, 0, 53, 90, 51, 106, 119, 55, 54, 111, 100, 85, 115, 57, 78, 75, 72, 73, 76, 119, 120, 104, 108, 81, 118, 50, 98, 122, 70, 72, 111, 73, 70, 48, 61},
			op:    "",
			table: "",
			sql:   "",
		},
		{
			name:  "small len",
			bytes: []byte{81, 0, 0},
			op:    "",
			table: "",
			sql:   "",
		},
		{
			name:  "empty",
			bytes: []byte{},
			op:    "",
			table: "",
			sql:   "",
		},
		{
			name:  "MySQL prepared statement",
			bytes: []byte{36, 0, 0, 0, 3, 0, 1, 69, 88, 69, 67, 85, 84, 69, 32, 109, 121, 95, 97, 99, 116, 111, 114, 115, 32, 85, 83, 73, 78, 71, 32, 64, 97, 99, 116, 111, 114, 95, 105, 100},
			op:    "EXECUTE",
			table: "my_actors",
			sql:   "EXECUTE my_actors USING @actor_id",
		},
	} {
		t.Run(ts.name, func(t *testing.T) {
			op, table, sql, _ := detectSQLPayload(false, ts.bytes)
			assert.Equal(t, ts.op, op)
			assert.Equal(t, ts.table, table)
			assert.Equal(t, ts.sql, sql)

			op, table, sql, _ = detectSQLPayload(true, ts.bytes)
			assert.Equal(t, ts.op, op)
			assert.Equal(t, ts.table, table)
			assert.Equal(t, ts.sql, sql)
		})
	}
}

type asciiSQLTest struct {
	name string
	s    string
	ok   bool
}

func TestIsASCII(t *testing.T) {
	for _, ts := range []asciiSQLTest{
		{
			name: "Positive test",
			s:    "This is a test_.-1234",
			ok:   true,
		},
		{
			name: "Bad char",
			s:    "This is\x00 a test_.-1234",
			ok:   false,
		},
		{
			name: "Empty",
			s:    "",
			ok:   true,
		},
	} {
		t.Run(ts.name, func(t *testing.T) {
			res := isASCII(ts.s)
			assert.Equal(t, ts.ok, res)
		})
	}
}
