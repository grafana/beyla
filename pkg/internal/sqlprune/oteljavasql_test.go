/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package sqlprune

var otalJavaSqlQueries = []string{
	"SELECT * FROM TABLE WHERE FIELD=1234", "SELECT * FROM TABLE WHERE FIELD=?",
	"SELECT * FROM TABLE WHERE FIELD = 1234", "SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD>=-1234", "SELECT * FROM TABLE WHERE FIELD>=?",

	"SELECT * FROM TABLE WHERE FIELD<-1234", "SELECT * FROM TABLE WHERE FIELD<?",

	"SELECT * FROM TABLE WHERE FIELD <.1234", "SELECT * FROM TABLE WHERE FIELD <?",
	"SELECT 1.2", "SELECT ?",
	"SELECT -1.2", "SELECT ?",
	"SELECT -1.2e-9", "SELECT ?",
	"SELECT 2E+9", "SELECT ?",
	"SELECT +0.2", "SELECT ?",
	"SELECT .2", "SELECT ?",
	"7", "?",
	".7", "?",
	"-7", "?",
	"+7", "?",
	"SELECT 0x0af764", "SELECT ?",
	"SELECT 0xdeadBEEF", "SELECT ?",
	"SELECT * FROM \"TABLE\"", "SELECT * FROM \"TABLE\"",

	// Not numbers but could be confused as such
	"SELECT A + B", "SELECT A + B",
	"SELECT -- comment", "SELECT -- comment",
	"SELECT * FROM TABLE123", "SELECT * FROM TABLE123",

	"SELECT FIELD2 FROM TABLE_123 WHERE X<>7", "SELECT FIELD2 FROM TABLE_123 WHERE X<>?",

	// Semi-nonsensical almost-numbers to elide or not
	"SELECT --83--...--8e+76e3E-1", "SELECT ?",
	"SELECT DEADBEEF", "SELECT DEADBEEF",
	"SELECT 123-45-6789", "SELECT ?",
	"SELECT 1/2/34", "SELECT ?/?/?",

	// Basic ' strings

	"SELECT * FROM TABLE WHERE FIELD = ''",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = 'words and spaces'",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = ' an escaped '' quote mark inside'",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = '\\\\'", "SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = '\"inside doubles\"'",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = '\"$$$$\"'",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = 'a single \" doublequote inside'",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	// Some databases allow using dollar-quoted strings

	"SELECT * FROM TABLE WHERE FIELD = $$$$", "SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = $$words and spaces$$",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = $$quotes '\" inside$$",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = $$\"''\"$$",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	"SELECT * FROM TABLE WHERE FIELD = $$\\\\$$", "SELECT * FROM TABLE WHERE FIELD = ?",

	// Unicode, including a unicode identifier with a trailing number

	"SELECT * FROM TABLEओ7 WHERE FIELD = 'ɣ'", "SELECT * FROM TABLEओ7 WHERE FIELD = ?",

	// whitespace normalization

	"SELECT    *    \t\r\nFROM  TABLE WHERE FIELD1 = 12344 AND FIELD2 = 5678",
	"SELECT * FROM TABLE WHERE FIELD1 = ? AND FIELD2 = ?",

	// hibernate/jpa query language
	"FROM TABLE WHERE FIELD=1234",
	"FROM TABLE WHERE FIELD=?",

	// SECOND SECTION
	// Some databases support/encourage " instead of ' with same escape rules
	"SELECT * FROM TABLE WHERE FIELD = \"\"",
	"SELECT * FROM TABLE WHERE FIELD = ?",
	"SELECT * FROM TABLE WHERE FIELD = \"words and spaces'\"",
	"SELECT * FROM TABLE WHERE FIELD = ?",
	"SELECT * FROM TABLE WHERE FIELD = \" an escaped \"\" quote mark inside\"",
	"SELECT * FROM TABLE WHERE FIELD = ?",
	"SELECT * FROM TABLE WHERE FIELD = \"\\\\\"", "SELECT * FROM TABLE WHERE FIELD = ?",
	"SELECT * FROM TABLE WHERE FIELD = \"'inside singles'\"",
	"SELECT * FROM TABLE WHERE FIELD = ?",
	"SELECT * FROM TABLE WHERE FIELD = \"'$$$$'\"",
	"SELECT * FROM TABLE WHERE FIELD = ?",
	"SELECT * FROM TABLE WHERE FIELD = \"a single ' singlequote inside\"",
	"SELECT * FROM TABLE WHERE FIELD = ?",

	// THIRD SECTION
	// Select
	"SELECT x, y, z FROM schema.table",
	"SELECT x, y, z FROM `schema table`",
	"SELECT x, y, z FROM \"schema table\"",
	"WITH subquery as (select a from b) SELECT x, y, z FROM table",

	"SELECT x, y, (select a from b) as z FROM table",
	"select delete, insert into, merge, update from table",
	"select col /* from table2 */ from table",
	"select col from table join anotherTable",
	"select col from (select * from anotherTable)",
	"select col from (select * from anotherTable) alias",
	"select col from table1 union select col from table2",
	"select col from table where col in (select * from anotherTable)",

	"select col from table1, table2",
	"select col from table1 t1, table2 t2",
	"select col from table1 as t1, table2 as t2",
	"select col from table where col in (1, 2, 3)",

	"select col from table order by col, col2",
	"select ąś∂ń© from źćļńĶ order by col, col2",
	"select 12345678",
	"/* update comment */ select * from table1",
	"select /*((*/abc from table",
	"SeLeCT * FrOm TAblE",
	"select next value in hibernate_sequence",

	// hibernate/jpa
	"FROM schema.table",
	"/* update comment */ from table1",

	// Insert
	" insert into table where lalala",
	"insert insert into table where lalala",
	"insert into db.table where lalala",
	"insert into `db table` where lalala",
	"insert into \"db table\" where lalala",
	"insert without i-n-t-o",

	// Delete
	"delete from table where something something",
	"delete from `my table` where something something",
	"delete from \"my table\" where something something",
	"delete from 12345678",
	"delete   (((",

	// Update
	"update table set answer=42",
	"update `my table` set answer=42",

	"update \"my table\" set answer=42",

	"update /*table",

	// Call
	"call test_proc()",
	"call test_proc",
	"call next value in hibernate_sequence",
	"call db.test_proc",

	// Merge
	"merge into table",
	"merge into `my table`",
	"merge into \"my table\"",
	"merge table (into is optional in some dbs)",
	"merge (into )))",

	// Unknown operation
	"and now for something completely different",
	"",
}
