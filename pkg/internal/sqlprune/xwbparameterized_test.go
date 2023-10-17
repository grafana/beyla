/*
Copyright 2017 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sqlprune

var (
	parameterizedValidSQL = []struct {
		input  string
		output string
	}{{
		input: "select ?",
	}, {
		input: "select ? from ?",
	}, {
		input: "select ? from ? where ? = ?",
	}, {
		input: "select ? from ? where ? = ?",
	}, {
		input: "select ? from ? // aa\n",
	}, {
		input: "select ? from ? // aa\n",
	}, {
		input: "select ? from ? -- aa\n",
	}, {
		input: "select ? from ? -- aa\n",
	}, {
		input: "select ? from ? # aa\n",
	}, {
		input: "select ? --aa\nfrom ?",
	}, {
		input: "select ? --aa\nfrom ?",
	}, {
		input: "select ? #aa\nfrom ?",
	}, {
		input: "select /* simplest */ ? from ?",
	}, {
		input: "select /* double star **/ ? from ?",
	}, {
		input: "select /* double */ /* comment */ ? from ?",
	}, {
		input: "select /* back-quote keyword */ `?` from ?",
	}, {
		input: "select /* back-quote num */ `?` from ?",
	}, {
		input: "select /* back-quote . */ `?` from ?",
	}, {
		input: "select /* back-quote back-quote */ `?``?` from ?",
	}, {
		input: "select /* back-quote unnecessary */ ? from `?`",
	}, {
		input: "select /* back-quote idnum */ ? from `a1`",
	}, {
		input: "select /* @ */ ? from ?",
	}, {
		input: "select /* \\0 */ '\\0' from ?",
	}, {
		input: "select ? /* drop this comment */ from ?",
	}, {
		input: "select /* union */ ? from ? union select ? from ?",
	}, {
		input: "select /* double union */ ? from ? union select ? from ? union select ? from ?",
	}, {
		input: "select /* union all */ ? from ? union all select ? from ?",
	}, {
		input: "select /* union distinct */ ? from ? union distinct select ? from ?",
	}, {
		input: "(select /* union parenthesized select */ ? from ? order by a) union select ? from ?",
	}, {
		input: "select /* union parenthesized select 2 */ ? from ? union (select ? from ?)",
	}, {
		input: "select /* union order by */ ? from ? union select ? from ? order by ?",
	}, {
		input: "select /* union order by limit lock */ ? from ? union select ? from ? order by ? limit ? for update",
	}, {
		input: "select /* union with limit on lhs */ ? from ? limit ? union select ? from ?",
	}, {
		input: "(select id, ? from ? order by id limit 1) union (select id, ? as ? from s order by id limit 1) order by ? limit 1",
	}, {
		input: "select ? from (select ? as ? from ?bl1 union select 2 from ?bl2) as t",
	}, {
		input: "select ? from ? join (select * from ?2 union select * from ?3) as t",
	}, {
		// Ensure this doesn't generate: ""select * from ? join ? on ? = ? join t3 on ? = ?".
		input: "select * from ? join ? on ? = ? join t3",
	}, {
		input: "select * from ? where col in (select ? from dual union select 2 from dual)",
	}, {
		input: "select * from ? where exists (select ? from ?2 union select ? from ?3)",
	}, {
		input: "select /* distinct */ distinct ? from ?",
	}, {
		input: "select /* straight_join */ straight_join ? from ?",
	}, {
		input: "select /* for update */ ? from ? for update",
	}, {
		input: "select /* lock in share mode */ ? from ? lock in share mode",
	}, {
		input: "select /* select list */ 1, 2 from ?",
	}, {
		input: "select /* * */ * from ?",
	}, {
		input: "select /* a.* */ a.* from ?",
	}, {
		input: "select /* a.b.* */ a.b.* from ?",
	}, {
		input: "select /* column alias */ ? ? from ?",
	}, {
		input: "select /* column alias with as */ ? as ? from ?",
	}, {
		input: "select /* keyword column alias */ ? as `By` from ?",
	}, {
		input: "select /* column alias as string */ ? as \"b\" from ?",
	}, {
		input: "select /* column alias as string without as */ ? \"b\" from ?",
	}, {
		input: "select /* a.* */ a.* from ?",
	}, {
		input: "select next value for t",
	}, {
		input: "select next value from ?",
	}, {
		input: "select next 10 values from ?",
	}, {
		input: "select next :a values from ?",
	}, {
		input: "select /* `By`.* */ `By`.* from ?",
	}, {
		input: "select /* select with bool expr */ ? = ? from ?",
	}, {
		input: "select /* case_when */ case when ? = ? then c end from ?",
	}, {
		input: "select /* case_when_else */ case when ? = ? then c else d end from ?",
	}, {
		input: "select /* case_when_when_else */ case when ? = ? then c when ? = d then d else d end from ?",
	}, {
		input: "select /* case */ case aa when ? = ? then c end from ?",
	}, {
		input: "select /* parenthesis */ ? from (t)",
	}, {
		input: "select /* parenthesis multi-table */ ? from (?, ?)",
	}, {
		input: "select /* table list */ ? from ?, ?",
	}, {
		input: "select /* parenthessis in table list ? */ ? from (?), ?",
	}, {
		input: "select /* parenthessis in table list 2 */ ? from ?, (?)",
	}, {
		input: "select /* use */ ? from ? use index (a) where ? = 1",
	}, {
		input: "select /* keyword index */ ? from ? use index (`By`) where ? = 1",
	}, {
		input: "select /* ignore */ ? from ? as ? ignore index (a), t3 use index (b) where ? = 1",
	}, {
		input: "select /* use */ ? from ? as ? use index (a), t3 use index (b) where ? = 1",
	}, {
		input: "select /* force */ ? from ? as ? force index (a), t3 force index (b) where ? = 1",
	}, {
		input: "select /* table alias */ ? from ? ?",
	}, {
		input: "select /* table alias with as */ ? from ? as ?",
	}, {
		input: "select /* string table alias */ ? from ? as '?'",
	}, {
		input: "select /* string table alias without as */ ? from ? '?'",
	}, {
		input: "select /* keyword table alias */ ? from ? as `By`",
	}, {
		input: "select /* join */ ? from ? join ?",
	}, {
		input: "select /* join on */ ? from ? join ? on ? = ?",
	}, {
		input: "select /* join on */ ? from ? join ? using (a)",
	}, {
		input: "select /* inner join */ ? from ? inner join ?",
	}, {
		input: "select /* cross join */ ? from ? cross join ?",
	}, {
		input: "select /* straight_join */ ? from ? straight_join ?",
	}, {
		input: "select /* straight_join on */ ? from ? straight_join ? on ? = ?",
	}, {
		input: "select /* left join */ ? from ? left join ? on ? = ?",
	}, {
		input: "select /* left join */ ? from ? left join ? using (a)",
	}, {
		input: "select /* left outer join */ ? from ? left outer join ? on ? = ?",
	}, {
		input: "select /* left outer join */ ? from ? left outer join ? using (a)",
	}, {
		input: "select /* right join */ ? from ? right join ? on ? = ?",
	}, {
		input: "select /* right join */ ? from ? right join ? using (a)",
	}, {
		input: "select /* right outer join */ ? from ? right outer join ? on ? = ?",
	}, {
		input: "select /* right outer join */ ? from ? right outer join ? using (a)",
	}, {
		input: "select /* natural join */ ? from ? natural join ?",
	}, {
		input: "select /* natural left join */ ? from ? natural left join ?",
	}, {
		input: "select /* natural left outer join */ ? from ? natural left join ?",
	}, {
		input: "select /* natural right join */ ? from ? natural right join ?",
	}, {
		input: "select /* natural right outer join */ ? from ? natural right join ?",
	}, {
		input: "select /* join on */ ? from ? join ? on ? = ?",
	}, {
		input: "select /* join using */ ? from ? join ? using (a)",
	}, {
		input: "select /* join using (a, b, c) */ ? from ? join ? using (a, b, c)",
	}, {
		input: "select /* s.t */ ? from s.t",
	}, {
		input: "select /* keyword schema & table name */ ? from `By`.`bY`",
	}, {
		input: "select /* select in from */ ? from (select ? from ?) as ?",
	}, {
		input: "select /* select in from with no as */ ? from (select ? from ?) ?",
	}, {
		input: "select /* where */ ? from ? where ? = ?",
	}, {
		input: "select /* and */ ? from ? where ? = ? and ? = c",
	}, {
		input: "select /* && */ ? from ? where ? = ? && ? = c",
	}, {
		input: "select /* or */ ? from ? where ? = ? or ? = c",
	}, {
		input: "select /* || */ ? from ? where ? = ? || ? = c",
	}, {
		input: "select /* not */ ? from ? where not ? = ?",
	}, {
		input: "select /* ! */ ? from ? where ? = !1",
	}, {
		input: "select /* bool is */ ? from ? where ? = ? is null",
	}, {
		input: "select /* bool is not */ ? from ? where ? = ? is not false",
	}, {
		input: "select /* true */ ? from ? where true",
	}, {
		input: "select /* false */ ? from ? where false",
	}, {
		input: "select /* false on left */ ? from ? where false = 0",
	}, {
		input: "select /* exists */ ? from ? where exists (select ? from ?)",
	}, {
		input: "select /* (boolean) */ ? from ? where not (a = b)",
	}, {
		input: "select /* in value list */ ? from ? where ? in (b, c)",
	}, {
		input: "select /* in select */ ? from ? where ? in (select ? from ?)",
	}, {
		input: "select /* not in */ ? from ? where ? not in (b, c)",
	}, {
		input: "select /* like */ ? from ? where ? like ?",
	}, {
		input: "select /* like escape */ ? from ? where ? like ? escape '!'",
	}, {
		input: "select /* not like */ ? from ? where ? not like ?",
	}, {
		input: "select /* not like escape */ ? from ? where ? not like ? escape '$'",
	}, {
		input: "select /* regexp */ ? from ? where ? regexp ?",
	}, {
		input: "select /* not regexp */ ? from ? where ? not regexp ?",
	}, {
		input: "select /* rlike */ ? from ? where ? rlike ?",
	}, {
		input: "select /* not rlike */ ? from ? where ? not rlike ?",
	}, {
		input: "select /* between */ ? from ? where ? between ? and c",
	}, {
		input: "select /* not between */ ? from ? where ? not between ? and c",
	}, {
		input: "select /* is null */ ? from ? where ? is null",
	}, {
		input: "select /* is not null */ ? from ? where ? is not null",
	}, {
		input: "select /* is true */ ? from ? where ? is true",
	}, {
		input: "select /* is not true */ ? from ? where ? is not true",
	}, {
		input: "select /* is false */ ? from ? where ? is false",
	}, {
		input: "select /* is not false */ ? from ? where ? is not false",
	}, {
		input: "select /* < */ ? from ? where ? < ?",
	}, {
		input: "select /* <= */ ? from ? where ? <= ?",
	}, {
		input: "select /* >= */ ? from ? where ? >= ?",
	}, {
		input: "select /* > */ ? from ? where ? > ?",
	}, {
		input: "select /* != */ ? from ? where ? != ?",
	}, {
		input: "select /* <> */ ? from ? where ? <> ?",
	}, {
		input: "select /* <=> */ ? from ? where ? <=> ?",
	}, {
		input: "select /* != */ ? from ? where ? != ?",
	}, {
		input: "select /* single value expre list */ ? from ? where ? in (b)",
	}, {
		input: "select /* select as ? value expression */ ? from ? where ? = (select ? from ?)",
	}, {
		input: "select /* parenthesised value */ ? from ? where ? = (b)",
	}, {
		input: "select /* over-parenthesize */ ((1)) from ? where ((a)) in (((1))) and ((a, b)) in ((((1, 1))), ((2, 2)))",
	}, {
		input: "select /* dot-parenthesize */ (a.b) from ? where (b.c) = 2",
	}, {
		input: "select /* & */ ? from ? where ? = ? & c",
	}, {
		input: "select /* & */ ? from ? where ? = ? & c",
	}, {
		input: "select /* | */ ? from ? where ? = ? | c",
	}, {
		input: "select /* ^ */ ? from ? where ? = ? ^ c",
	}, {
		input: "select /* + */ ? from ? where ? = ? + c",
	}, {
		input: "select /* - */ ? from ? where ? = ? - c",
	}, {
		input: "select /* * */ ? from ? where ? = ? * c",
	}, {
		input: "select /* / */ ? from ? where ? = ? / c",
	}, {
		input: "select /* % */ ? from ? where ? = ? % c",
	}, {
		input: "select /* div */ ? from ? where ? = ? div c",
	}, {
		input: "select /* MOD */ ? from ? where ? = ? MOD c",
	}, {
		input: "select /* << */ ? from ? where ? = ? << c",
	}, {
		input: "select /* >> */ ? from ? where ? = ? >> c",
	}, {
		input: "select /* % no space */ ? from ? where ? = b%c",
	}, {
		input: "select /* u+ */ ? from ? where ? = +b",
	}, {
		input: "select /* u- */ ? from ? where ? = -b",
	}, {
		input: "select /* u~ */ ? from ? where ? = ~b",
	}, {
		input: "select /* -> */ a.b -> 'ab' from ?",
	}, {
		input: "select /* -> */ a.b ->> 'ab' from ?",
	}, {
		input: "select /* empty function */ ? from ? where ? = b()",
	}, {
		input: "select /* function with ? param */ ? from ? where ? = b(c)",
	}, {
		input: "select /* function with many params */ ? from ? where ? = b(c, d)",
	}, {
		input: "select /* function with distinct */ count(distinct a) from ?",
	}, {
		input: "select /* if as func */ ? from ? where ? = if(b)",
	}, {
		input: "select /* current_timestamp as func */ current_timestamp() from ?",
	}, {
		input: "select /* mod as func */ ? from ?ab where mod(b, 2) = 0",
	}, {
		input: "select /* database as func no param */ database() from ?",
	}, {
		input: "select /* database as func ? param */ database(1) from ?",
	}, {
		input: "select /* ? */ ? from ?",
	}, {
		input: "select /* a.b */ a.b from ?",
	}, {
		input: "select /* a.b.c */ a.b.c from ?",
	}, {
		input: "select /* keyword a.b */ `By`.`bY` from ?",
	}, {
		input: "select /* string */ 'a' from ?",
	}, {
		input: "select /* double quoted string */ \"a\" from ?",
	}, {
		input: "select /* quote quote in string */ 'a''a' from ?",
	}, {
		input: "select /* double quote quote in string */ \"a\"\"a\" from ?",
	}, {
		input: "select /* quote in double quoted string */ \"a'a\" from ?",
	}, {
		input: "select /* backslash quote in string */ 'a\\'a' from ?",
	}, {
		input: "select /* literal backslash in string */ 'a\\\\na' from ?",
	}, {
		input: "select /* all escapes */ '\\0\\'\\\"\\b\\n\\r\\t\\Z\\\\' from ?",
	}, {
		input: "select /* non-escape */ '\\x' from ?",
	}, {
		input: "select /* unescaped backslash */ '\\n' from ?",
	}, {
		input: "select /* value argument */ :a from ?",
	}, {
		input: "select /* value argument with digit */ :a1 from ?",
	}, {
		input: "select /* value argument with dot */ :a.b from ?",
	}, {
		input: "select /* positional argument */ ? from ?",
	}, {
		input: "select /* multiple positional arguments */ ?, ? from ?",
	}, {
		input: "select /* list arg */ * from ? where ? in ::list",
	}, {
		input: "select /* list arg not in */ * from ? where ? not in ::list",
	}, {
		input: "select /* null */ null from ?",
	}, {
		input: "select /* octal */ 010 from ?",
	}, {
		input: "select /* hex */ x'f0A1' from ?",
	}, {
		input: "select /* hex caps */ X'F0a1' from ?",
	}, {
		input: "select /* bit literal */ b'0101' from ?",
	}, {
		input: "select /* bit literal caps */ B'010011011010' from ?",
	}, {
		input: "select /* 0x */ 0xf0 from ?",
	}, {
		input: "select /* float */ 0.1 from ?",
	}, {
		input: "select /* group by */ ? from ? group by ?",
	}, {
		input: "select /* having */ ? from ? having ? = ?",
	}, {
		input: "select /* simple order by */ ? from ? order by ?",
	}, {
		input: "select /* order by asc */ ? from ? order by ? asc",
	}, {
		input: "select /* order by desc */ ? from ? order by ? desc",
	}, {
		input: "select /* order by null */ ? from ? order by null",
	}, {
		input: "select /* limit ? */ ? from ? limit ?",
	}, {
		input: "select /* limit a,b */ ? from ? limit a, ?",
	}, {
		input: "select /* binary unary */ a- -b from ?",
	}, {
		input: "select /* - - */ - -b from ?",
	}, {
		input: "select /* binary binary */ binary  binary ? from ?",
	}, {
		input: "select /* binary ~ */ binary  ~b from ?",
	}, {
		input: "select /* ~ binary */ ~ binary ? from ?",
	}, {
		input: "select /* interval */ adddate('2008-01-02', interval 31 day) from ?",
	}, {
		input: "select /* interval keyword */ adddate('2008-01-02', interval ? year) from ?",
	}, {
		input: "select /* dual */ ? from dual",
	}, {
		input: "select /* Dual */ ? from Dual",
	}, {
		input: "select /* DUAL */ ? from Dual",
	}, {
		input: "select /* column as bool in where */ ? from ? where ?",
	}, {
		input: "select /* OR of columns in where */ * from ? where ? or ?",
	}, {
		input: "select /* OR of mixed columns in where */ * from ? where ? = 5 or ? and c is not null",
	}, {
		input: "select /* OR in select columns */ (a or b) from ? where c = 5",
	}, {
		input: "select /* bool as select value */ a, true from ?",
	}, {
		input: "select /* bool column in ON clause */ * from ? join s on t.id = s.id and s.foo where t.bar",
	}, {
		input: "select /* bool in order by */ * from ? order by ? is null or ? asc",
	}, {
		input: "select /* string in case statement */ if(max(case ? when 'foo' then ? else 0 end) = 1, 'foo', 'bar') as foobar from ?",
	}, {
		input: "/*!show databases*/",
	}, {
		input: "select /*!40101 * from*/ t",
	}, {
		input: "select /*! * from*/ t",
	}, {
		input: "select /*!* from*/ t",
	}, {
		input: "select /*!401011 from*/ t",
	}, {
		input: "select /* dual */ ? from dual",
	}, {
		input: "insert /* simple */ into ? values (1)",
	}, {
		input: "insert /* a.b */ into a.b values (1)",
	}, {
		input: "insert /* multi-value */ into ? values (1, 2)",
	}, {
		input: "insert /* multi-value list */ into ? values (1, 2), (3, 4)",
	}, {
		input: "insert /* no values */ into ? values ()",
	}, {
		input: "insert /* set */ into ? set ? = 1, ? = 2",
	}, {
		input: "insert /* set default */ into ? set ? = default, ? = 2",
	}, {
		input: "insert /* value expression list */ into ? values (a + 1, 2 * 3)",
	}, {
		input: "insert /* default */ into ? values (default, 2 * 3)",
	}, {
		input: "insert /* column list */ into a(a, b) values (1, 2)",
	}, {
		input: "insert into a(a, b) values (1, ifnull(null, default(b)))",
	}, {
		input: "insert /* qualified column list */ into a(a, b) values (1, 2)",
	}, {
		input: "insert /* qualified columns */ into ? (t.a, t.b) values (1, 2)",
	}, {
		input: "insert /* select */ into ? select b, c from d",
	}, {
		input: "insert /* no cols & paren select */ into a(select * from ?)",
	}, {
		input: "insert /* cols & paren select */ into a(a,b,c) (select * from ?)",
	}, {
		input: "insert /* cols & union with paren select */ into a(b, c) (select d, e from f) union (select g from h)",
	}, {
		input: "insert /* on duplicate */ into ? values (1, 2) on duplicate key update ? = func(a), c = d",
	}, {
		input: "insert /* bool in insert value */ into ? values (1, true, false)",
	}, {
		input: "insert /* bool in on duplicate */ into ? values (1, 2) on duplicate key update ? = false, c = d",
	}, {
		input: "insert /* bool in on duplicate */ into ? values (1, 2, 3) on duplicate key update ? = values(b), c = d",
	}, {
		input: "insert /* bool in on duplicate */ into ? values (1, 2, 3) on duplicate key update ? = values(a.b), c = d",
	}, {
		input: "insert /* bool expression on duplicate */ into ? values (1, 2) on duplicate key update ? = func(a), c = ? > d",
	}, {
		input: "update /* simple */ ? set ? = 3",
	}, {
		input: "update /* a.b */ a.b set ? = 3",
	}, {
		input: "update /* list */ ? set ? = 3, c = 4",
	}, {
		input: "update /* expression */ ? set ? = 3 + 4",
	}, {
		input: "update /* where */ ? set ? = 3 where ? = ?",
	}, {
		input: "update /* order */ ? set ? = 3 order by c desc",
	}, {
		input: "update /* limit */ ? set ? = 3 limit c",
	}, {
		input: "update /* bool in update */ ? set ? = true",
	}, {
		input: "update /* bool expr in update */ ? set ? = 5 > 2",
	}, {
		input: "update /* bool in update where */ ? set ? = 5 where c",
	}, {
		input: "update /* table qualifier */ ? set a.b = 3",
	}, {
		input: "update /* table qualifier */ ? set t.a.b = 3",
	}, {
		input: "update /* table alias */ tt aa set aa.cc = 3",
	}, {
		input: "update (select id from foo) subqalias set id = 4",
	}, {
		input: "update foo f, bar ? set f.id = b.id where b.name = 'test'",
	}, {
		input: "update foo f join bar ? on f.name = b.name set f.id = b.id where b.name = 'test'",
	}, {
		input: "delete /* simple */ from ?",
	}, {
		input: "delete /* a.b */ from ?.?",
	}, {
		input: "delete /* where */ from ? where ? = ?",
	}, {
		input: "delete /* order */ from ? order by ? desc",
	}, {
		input: "delete /* limit */ from ? limit ?",
	}, {
		input: "delete ? from ? join ? on a.id = b.id where b.name = 'test'",
	}, {
		input: "delete a, ? from a, ? where a.id = b.id and b.name = 'test'",
	}, {
		input: "delete from a1, a2 using ? as a1 inner join ? as a2 where a1.id=a2.id",
	}, {
		input: "set /* simple */ ? = 3",
	}, {
		input: "set #simple\n ? = 4",
	}, {
		input: "set character_set_results = utf8",
	}, {
		input: "set @@session.autocommit = true",
	}, {
		input: "set @@session.`autocommit` = true",
	}, {
		input: "set @@session.'autocommit' = true",
	}, {
		input: "set @@session.\"autocommit\" = true",
	}, {
		input: "set names utf8 collate foo",
	}, {
		input: "set character set utf8",
	}, {
		input: "set character set 'utf8'",
	}, {
		input: "set character set \"utf8\"",
	}, {
		input: "set charset default",
	}, {
		input: "set session wait_timeout = 3600",
	}, {
		input: "set /* list */ ? = 3, ? = 4",
	}, {
		input: "set /* mixed list */ ? = 3, names 'utf8', charset 'ascii', ? = 4",
	}, {
		input: "set session transaction isolation level repeatable read",
	}, {
		input: "set global transaction isolation level repeatable read",
	}, {
		input: "set transaction isolation level repeatable read",
	}, {
		input: "set transaction isolation level read committed",
	}, {
		input: "set transaction isolation level read uncommitted",
	}, {
		input: "set transaction isolation level serializable",
	}, {
		input: "set transaction read write",
	}, {
		input: "set transaction read only",
	}, {
		input: "set tx_read_only = 1",
	}, {
		input: "set tx_read_only = 0",
	}, {
		input: "set tx_isolation = 'repeatable read'",
	}, {
		input: "set tx_isolation = 'read committed'",
	}, {
		input: "set tx_isolation = 'read uncommitted'",
	}, {
		input: "set tx_isolation = 'serializable'",
	}, {
		input: "set sql_safe_updates = 0",
	}, {
		input: "set sql_safe_updates = 1",
	}, {
		input: "alter ignore table ? add foo",
	}, {
		input: "alter table ? add foo",
	}, {
		input: "alter table ? add spatial key foo (column1)",
	}, {
		input: "alter table ? add unique key foo (column1)",
	}, {
		input: "alter table `By` add foo",
	}, {
		input: "alter table ? alter foo",
	}, {
		input: "alter table ? change foo",
	}, {
		input: "alter table ? modify foo",
	}, {
		input: "alter table ? drop foo",
	}, {
		input: "alter table ? disable foo",
	}, {
		input: "alter table ? enable foo",
	}, {
		input: "alter table ? order foo",
	}, {
		input: "alter table ? default foo",
	}, {
		input: "alter table ? discard foo",
	}, {
		input: "alter table ? import foo",
	}, {
		input: "alter table ? rename ?",
	}, {
		input: "alter table `By` rename `bY`",
	}, {
		input: "alter table ? rename to ?",
	}, {
		input: "alter table ? rename as ?",
	}, {
		input: "alter table ? rename index foo to bar",
	}, {
		input: "alter table ? rename key foo to bar",
	}, {
		input: "alter table e auto_increment = 20",
	}, {
		input: "alter table e character set = 'ascii'",
	}, {
		input: "alter table e default character set = 'ascii'",
	}, {
		input: "alter table e comment = 'hello'",
	}, {
		input: "alter table ? reorganize partition ? into (partition c values less than (?), partition d values less than (maxvalue))",
	}, {
		input: "alter table ? partition by range (id) (partition p0 values less than (10), partition p1 values less than (maxvalue))",
	}, {
		input: "alter table ? add column id int",
	}, {
		input: "alter table ? add index idx (id)",
	}, {
		input: "alter table ? add fulltext index idx (id)",
	}, {
		input: "alter table ? add spatial index idx (id)",
	}, {
		input: "alter table ? add foreign key",
	}, {
		input: "alter table ? add primary key",
	}, {
		input: "alter table ? add constraint",
	}, {
		input: "alter table ? add id",
	}, {
		input: "alter table ? drop column id int",
	}, {
		input: "alter table ? drop partition p2712",
	}, {
		input: "alter table ? drop index idx (id)",
	}, {
		input: "alter table ? drop fulltext index idx (id)",
	}, {
		input: "alter table ? drop spatial index idx (id)",
	}, {
		input: "alter table ? drop foreign key",
	}, {
		input: "alter table ? drop primary key",
	}, {
		input: "alter table ? drop constraint",
	}, {
		input: "alter table ? drop id",
	}, {
		input: "alter table ? add vindex hash (id)",
	}, {
		input: "alter table ? add vindex `hash` (`id`)",
	}, {
		input: "alter table ? add vindex hash (id) using `hash`",
	}, {
		input: "alter table ? add vindex `add` (`add`)",
	}, {
		input: "alter table ? add vindex hash (id) using hash",
	}, {
		input: "alter table ? add vindex hash (id) using `hash`",
	}, {
		input: "alter table user add vindex name_lookup_vdx (name) using lookup_hash with owner=user, table=name_user_idx, from=name, to=user_id",
	}, {
		input: "alter table user2 add vindex name_lastname_lookup_vdx (name,lastname) using lookup with owner=`user`, table=`name_lastname_keyspace_id_map`, from=`name,lastname`, to=`keyspace_id`",
	}, {
		input: "alter table ? drop vindex hash",
	}, {
		input: "alter table ? drop vindex `hash`",
	}, {
		input: "alter table ? drop vindex hash",
	}, {
		input: "alter table ? drop vindex `add`",
	}, {
		input: "create table ?",
	}, {
		input: "create table ? (\n\t`a` int\n)",
	}, {
		input: "create table `by` (\n\t`by` char\n)",
	}, {
		input: "create table if not exists ? (\n\t`a` int\n)",
	}, {
		input: "create table ? ignore me this is garbage",
	}, {
		input: "create table ? (a int, ? char, c garbage)",
	}, {
		input: "create vindex hash_vdx using hash",
	}, {
		input: "create vindex lookup_vdx using lookup with owner=user, table=name_user_idx, from=name, to=user_id",
	}, {
		input: "create vindex xyz_vdx using xyz with param1=hello, param2='world', param3=123",
	}, {
		input: "create index ? on ?",
	}, {
		input: "create unique index ? on ?",
	}, {
		input: "create unique index ? using foo on ?",
	}, {
		input: "create fulltext index ? using foo on ?",
	}, {
		input: "create spatial index ? using foo on ?",
	}, {
		input: "create view ?",
	}, {
		input: "create or replace view ?",
	}, {
		input: "alter view ?",
	}, {
		input: "drop view ?",
	}, {
		input: "drop table ?",
	}, {
		input: "drop table if exists ?",
	}, {
		input: "drop view if exists ?",
	}, {
		input: "drop index ? on ?",
	}, {
		input: "analyze table ?",
	}, {
		input: "show binary logs",
	}, {
		input: "show binlog events",
	}, {
		input: "show character set",
	}, {
		input: "show character set like '%foo'",
	}, {
		input: "show collation",
	}, {
		input: "show create database d",
	}, {
		input: "show create event e",
	}, {
		input: "show create function f",
	}, {
		input: "show create procedure p",
	}, {
		input: "show create table t",
	}, {
		input: "show create trigger t",
	}, {
		input: "show create user u",
	}, {
		input: "show create view v",
	}, {
		input: "show databases",
	}, {
		input: "show engine INNOD?",
	}, {
		input: "show engines",
	}, {
		input: "show storage engines",
	}, {
		input: "show errors",
	}, {
		input: "show events",
	}, {
		input: "show function code func",
	}, {
		input: "show function status",
	}, {
		input: "show grants for 'root@localhost'",
	}, {
		input: "show index from ?able",
	}, {
		input: "show indexes from ?able",
	}, {
		input: "show keys from ?able",
	}, {
		input: "show master status",
	}, {
		input: "show open tables",
	}, {
		input: "show plugins",
	}, {
		input: "show privileges",
	}, {
		input: "show procedure code p",
	}, {
		input: "show procedure status",
	}, {
		input: "show processlist",
	}, {
		input: "show full processlist",
	}, {
		input: "show profile cpu for query 1",
	}, {
		input: "show profiles",
	}, {
		input: "show relaylog events",
	}, {
		input: "show slave hosts",
	}, {
		input: "show slave status",
	}, {
		input: "show status",
	}, {
		input: "show global status",
	}, {
		input: "show session status",
	}, {
		input: "show table status",
	}, {
		input: "show tables",
	}, {
		input: "show tables like '%keyspace%'",
	}, {
		input: "show tables where ? = 0",
	}, {
		input: "show tables from ?",
	}, {
		input: "show tables from ? where ? = 0",
	}, {
		input: "show tables from ? like '%keyspace%'",
	}, {
		input: "show full tables",
	}, {
		input: "show full tables from ?",
	}, {
		input: "show full tables in ?",
	}, {
		input: "show full tables from ? like '%keyspace%'",
	}, {
		input: "show full tables from ? where ? = 0",
	}, {
		input: "show full tables like '%keyspace%'",
	}, {
		input: "show full tables where ? = 0",
	}, {
		input: "show triggers",
	}, {
		input: "show variables",
	}, {
		input: "show global variables",
	}, {
		input: "show session variables",
	}, {
		input: "show vindexes",
	}, {
		input: "show vindexes on t",
	}, {
		input: "show vitess_keyspaces",
	}, {
		input: "show vitess_shards",
	}, {
		input: "show vitess_tablets",
	}, {
		input: "show vschema_tables",
	}, {
		input: "show warnings",
	}, {
		input: "show foobar",
	}, {
		input: "show foobar like select * from ?able where syntax is 'ignored'",
	}, {
		input: "use d?",
	}, {
		input: "use duplicate",
	}, {
		input: "use `ks:-80@master`",
	}, {
		input: "describe foobar",
	}, {
		input: "desc foobar",
	}, {
		input: "explain foobar",
	}, {
		input: "truncate table foo",
	}, {
		input: "truncate foo",
	}, {
		input: "repair foo",
	}, {
		input: "optimize foo",
	}, {
		input: "select /* EQ true */ ? from ? where ? = true",
	}, {
		input: "select /* EQ false */ ? from ? where ? = false",
	}, {
		input: "select /* NE true */ ? from ? where ? != true",
	}, {
		input: "select /* NE false */ ? from ? where ? != false",
	}, {
		input: "select /* LT true */ ? from ? where ? < true",
	}, {
		input: "select /* LT false */ ? from ? where ? < false",
	}, {
		input: "select /* GT true */ ? from ? where ? > true",
	}, {
		input: "select /* GT false */ ? from ? where ? > false",
	}, {
		input: "select /* LE true */ ? from ? where ? <= true",
	}, {
		input: "select /* LE false */ ? from ? where ? <= false",
	}, {
		input: "select /* GE true */ ? from ? where ? >= true",
	}, {
		input: "select /* GE false */ ? from ? where ? >= false",
	}, {
		input: "select * from ? order by ? collate utf8_general_ci",
	}, {
		input: "select k collate latin1_german2_ci as k1 from ? order by k1 asc",
	}, {
		input: "select * from ? group by ? collate utf8_general_ci",
	}, {
		input: "select MAX(k collate latin1_german2_ci) from ?",
	}, {
		input: "select distinct k collate latin1_german2_ci from ?",
	}, {
		input: "select * from ? where 'Müller' collate latin1_german2_ci = k",
	}, {
		input: "select * from ? where k like 'Müller' collate latin1_german2_ci",
	}, {
		input: "select k from ? group by k having k = 'Müller' collate latin1_german2_ci",
	}, {
		input: "select k from ? join ? order by ? collate latin1_german2_ci asc, ? collate latin1_german2_ci asc",
	}, {
		input: "select k collate 'latin1_german2_ci' as k1 from ? order by k1 asc",
	}, {
		input: "select /* drop trailing semicolon */ ? from dual;",
	}, {
		input: "select /* cache directive */ sql_no_cache 'foo' from ?",
	}, {
		input: "select binary 'a' = 'A' from ?",
	}, {
		input: "select ? from ? where foo = _binary 'bar'",
	}, {
		input: "select ? from ? where foo = _binary'bar'",
	}, {
		input: "select match(a) against ('foo') from ?",
	}, {
		input: "select match(a1, a2) against ('foo' in natural language mode with query expansion) from ?",
	}, {
		input: "select title from video as v where match(v.title, v.tag) against ('DEMO' in boolean mode)",
	}, {
		input: "select name, group_concat(score) from ? group by name",
	}, {
		input: "select name, group_concat(distinct id, score order by id desc separator ':') from ? group by name",
	}, {
		input: "select * from ? partition (p0)",
	}, {
		input: "select * from ? partition (p0, p1)",
	}, {
		input: "select e.id, s.city from employees as e join stores partition (p1) as s on e.store_id = s.id",
	}, {
		input: "select truncate(120.3333, 2) from dual",
	}, {
		input: "update ? partition (p0) set ? = 1",
	}, {
		input: "insert into ? partition (p0) values (1, 'asdf')",
	}, {
		input: "insert into ? select * from ? partition (p0)",
	}, {
		input: "replace into ? partition (p0) values (1, 'asdf')",
	}, {
		input: "delete from ? partition (p0) where ? = 1",
	}, {
		input: "stream * from ?",
	}, {
		input: "stream /* comment */ * from ?",
	}, {
		input: "begin",
	}, {
		input: "start transaction",
	}, {
		input: "commit",
	}, {
		input: "rollback",
	}, {
		input: "create database ?",
	}, {
		input: "create schema ?",
	}, {
		input: "create database if not exists ?",
	}, {
		input: "drop database ?",
	}, {
		input: "drop schema ?",
	}, {
		input: "drop database if exists ?",
	}}
)
