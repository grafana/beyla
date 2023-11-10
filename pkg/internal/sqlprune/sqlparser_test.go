/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 * Copyright Grafana Labs
 * SPDX-License-Identifier: Apache-2.0
 */
package sqlprune

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSQLExtraction(t *testing.T) {
	type result struct {
		op    string
		table string
	}

	t.Run("test SELECT", func(t *testing.T) {
		tests := map[string]result{
			"SELECT t.id, t.name FROM ACCESS_TOKENS t, SECURITY_POLICIES sp WHERE sp.id=t.security_policy_id AND sp.org_id=?": {op: "SELECT", table: "ACCESS_TOKENS,SECURITY_POLICIES"},
			"SELECT * FROM TABLE WHERE FIELD=1234": {op: "SELECT", table: ""},
			"SELECT * FROM ZOOM WHERE FIELD=1234":  {op: "SELECT", table: "ZOOM"},
			`SELECT
				t.id,
				t.name,
			FROM
				ACCESS_TOKENS t
			INNER JOIN
				security_policies sp ON sp.id = t.security_policy_id AND sp.org_id = ?
			WHERE
				1=1 AND t.org_id = ? AND (t.expired IS NULL OR t.expired = 0)
			ORDER BY
				t.date ASC,
				t.id ASC
			LIMIT 1`: {op: "SELECT", table: "ACCESS_TOKENS,security_policies"},
			`SELECT
			t.id,
			t.name,
		FROM
			front.ACCESS_TOKENS t
		INNER JOIN
			back.security_policies sp ON sp.id = t.security_policy_id AND sp.org_id = ?
		WHERE
			1=1 AND t.org_id = ? AND (t.expired IS NULL OR t.expired = 0)
		ORDER BY
			t.date ASC,
			t.id ASC
		LIMIT 1`: {op: "SELECT", table: "front.ACCESS_TOKENS,back.security_policies"},
			`SELECT
				p.id,
				p.name,
				(
					SELECT
						JSON_ARRAYAGG(
							JSON_OBJECT(
								'id',
								'type',
							)
						)
					FROM
						customers c
					WHERE c.is = p.id AND c.inactive IS NULL
				) as bananas`: {op: "SELECT", table: "customers"},
			"SELECT 1.2":                              {op: "SELECT", table: ""},
			"SELECT 0xdeadBEEF":                       {op: "SELECT", table: ""},
			"SELECT A + B":                            {op: "SELECT", table: ""},
			"SELECT * FROM TABLE123":                  {op: "SELECT", table: "TABLE123"},
			"SELECT FIELD2 FROM TABLE_123 WHERE X<>7": {op: "SELECT", table: "TABLE_123"},
			"SELECT * FROM TABLE t WHERE FIELD = ' an escaped '' quote mark inside' JOIN ABC ON t.id=ABC.id": {op: "SELECT", table: "t,ABC"},
			"select col from table_a where col in (select * from anotherTable)":                              {op: "SELECT", table: "table_a,anotherTable"},
			"SELECT * FROM TABLE123; SELECT * FROM USERS":                                                    {op: "SELECT", table: "TABLE123,USERS"},
		}

		for q, r := range tests {
			op, tab := SQLParseOperationAndTable(q)
			assert.Equal(t, r, result{op: op, table: tab})
		}
	})

	t.Run("test INSERT", func(t *testing.T) {
		tests := map[string]result{
			" insert into users where lalala":                              {op: "INSERT", table: "users"},
			"insert into `db table` where lalala":                          {op: "INSERT", table: "db table"},
			"insert without i-n-t-o":                                       {op: "INSERT", table: ""},
			"insert into db.table where lalala":                            {op: "INSERT", table: "db"},
			"insert into db.users where lalala":                            {op: "INSERT", table: "db.users"},
			"INSERT INTO table1 (column1) SELECT col1 FROM table2":         {op: "INSERT", table: "table1"},
			"INSERT INTO db1.table1 (column1) SELECT col1 FROM db2.table2": {op: "INSERT", table: "db1.table1"},
		}

		for q, r := range tests {
			op, tab := SQLParseOperationAndTable(q)
			assert.Equal(t, r, result{op: op, table: tab})
		}
	})

	t.Run("test DELETE", func(t *testing.T) {
		tests := map[string]result{
			"delete from table where something something":      {op: "DELETE", table: ""},
			"delete from `my table` where something something": {op: "DELETE", table: "my table"},
			"delete from db.users where something something":   {op: "DELETE", table: "db.users"},
			"delete from 12345678":                             {op: "DELETE", table: ""},
			"delete   (((":                                     {op: "DELETE", table: ""},
		}

		for q, r := range tests {
			op, tab := SQLParseOperationAndTable(q)
			assert.Equal(t, r, result{op: op, table: tab})
		}
	})

	t.Run("test UPDATE", func(t *testing.T) {
		tests := map[string]result{
			"update table set answer=42":         {op: "UPDATE", table: ""},
			"update `my table` set answer=42":    {op: "UPDATE", table: "my table"},
			"update db.`my table` set answer=42": {op: "UPDATE", table: "db.my table"},
			"update /*table":                     {op: "UPDATE", table: ""},
		}

		for q, r := range tests {
			op, tab := SQLParseOperationAndTable(q)
			assert.Equal(t, r, result{op: op, table: tab})
		}
	})

	t.Run("test Non-sense", func(t *testing.T) {
		tests := map[string]result{
			"and now for something completely different": {op: "", table: ""},
			"ąś∂ń© from źćļńĶ order by col, col2":        {op: "", table: ""},
			"":         {op: "", table: ""},
			"//select": {op: "", table: ""},
		}

		for q, r := range tests {
			op, tab := SQLParseOperationAndTable(q)
			assert.Equal(t, r, result{op: op, table: tab})
		}
	})
}
