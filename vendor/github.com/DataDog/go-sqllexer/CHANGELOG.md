# Changelog

## v0.2.5

### Bug Fixes

- **Fix truncated obfuscation of PostgreSQL strings containing backslashes** ([#110](https://github.com/DataDog/go-sqllexer/pull/110))
  Backslash is now treated as a normal character in PostgreSQL strings (except `E'...'` strings), so these strings no longer truncate the obfuscated query. In all dialects, a doubled quote (`''`) inside a string now stays part of one literal, which can slightly change obfuscated output.

- **Keep MySQL qualified identifiers intact when spaced around dots** ([#108](https://github.com/DataDog/go-sqllexer/pull/108))
  Names like `db . table` (as found in `performance_schema` digest text) are now normalized to `db.table` and reported as a single table in metadata.

## v0.2.4

### Bug Fixes

- **Don't treat backslash as a string escape in SQL Server and Oracle** ([#103](https://github.com/DataDog/go-sqllexer/pull/103))
  SQL Server (T-SQL) and Oracle follow ANSI-SQL string semantics, where backslash is an ordinary character and a quote inside a literal is escaped by doubling it (`''`). The lexer previously treated `\` as an escape character for all dialects, so a literal like `ESCAPE '\'` had its closing quote misread as escaped, causing the scan to swallow the rest of the batch up to the next quote and truncate the obfuscated query.

## v0.2.3

### Bug Fixes

- **Preserve bracket-quoted T-SQL identifiers containing spaces** ([#101](https://github.com/DataDog/go-sqllexer/pull/101))
  Bracket-quoted identifiers whose content contains whitespace (e.g. `[Column With Spaces]`) are no longer de-bracketed during normalization. Stripping the brackets produces bare spaces in identifier position, which breaks query structure. Simple identifiers (`[schema]`, `[table]`) and dot-joined multi-part identifiers (`[schema].[table]`) are unaffected and continue to be de-bracketed as before. A secondary fix suppresses the spurious space that the normalizer was inserting between a dot-suffixed token and the bracket-quoted identifier that follows it (e.g. `t. [Col]` → `t.[Col]`).

## v0.2.2

### Bug Fixes

- **Obfuscate EXTRACT field keywords** ([#98](https://github.com/DataDog/go-sqllexer/pull/98))
  The obfuscator now replaces the field argument of `EXTRACT(field FROM source)` with a placeholder when it matches a known PostgreSQL field name (`epoch`, `year`, `month`, `dow`, `isodow`, `microseconds`, `timezone_hour`, etc.). Previously, queries captured via `pg_stat_activity` kept `epoch` as an unquoted identifier while queries from `pg_stat_statements` had it normalized to `$1` (and then to `?`), splitting one logical query across two DBM signatures. Both code paths now converge on `EXTRACT(? FROM source)`. Bare `epoch`/`year`/etc. outside an `EXTRACT(...)` call (e.g. as a column reference) and unrecognized field names are left untouched.

- **Fix handling of PostgreSQL VACUUM commands** ([#96](https://github.com/DataDog/go-sqllexer/pull/96))
  Fixes a typo and reclassifies `VACUUM` from a generic keyword to a command so it is correctly extracted into statement metadata.

- **Handle multiline comment after keyword** ([#89](https://github.com/DataDog/go-sqllexer/pull/89))
  The lexer now correctly tokenizes SQL keywords when they are directly followed by a multiline comment (e.g. `select/**/*/**/from/**/events`). Previously, the leading `/` of the comment could be absorbed into the preceding token, breaking keyword detection.

### Performance Improvements

- **Avoid allocation in `isExtractFieldKeyword`** ([#99](https://github.com/DataDog/go-sqllexer/pull/99))
  Replaces a `strings.ToUpper` + map lookup with an allocation-free `strings.EqualFold` scan over a small slice of EXTRACT field names.

## v0.2.1

### Bug Fixes

- **Fix table name metadata extraction** ([#91](https://github.com/DataDog/go-sqllexer/pull/91))
  The normalizer now correctly extracts all table names from comma-separated table lists (e.g., `SELECT * FROM t1, t2`). Previously, only the first table after a table indicator keyword was collected. This also adds `LATERAL` as a recognized keyword so it is no longer misidentified as a table name during metadata extraction.

### Maintenance

- **Pin GitHub Actions** ([#90](https://github.com/DataDog/go-sqllexer/pull/90))

## v0.2.0

### Breaking Changes

- **Minimum Go version bumped to 1.25** ([#87](https://github.com/DataDog/go-sqllexer/pull/87))
  The `go.mod` minimum Go version has been raised to Go 1.25. CI now tests through Go 1.25.7.

### Bug Fixes

- **Fix multi-byte UTF-8 character handling** ([#85](https://github.com/DataDog/go-sqllexer/pull/85))
  The lexer now correctly advances by the full rune length when scanning unknown tokens, double-quoted identifiers, and other multi-byte UTF-8 sequences (e.g., full-width punctuation, CJK characters). Previously, multi-byte characters could be incorrectly split into separate byte-level tokens or cause misaligned scans. This includes a fix for truncated UTF-8 sequences at the end of input.

### Performance Improvements

- **Use fixed-size array for trie nodes instead of a hashmap** ([#84](https://github.com/DataDog/go-sqllexer/pull/84))
  The keyword trie's `children` field was changed from `map[rune]*trieNode` to a fixed-size `[27]*trieNode` array (A–Z + underscore). This replaces map lookups with direct array indexing during keyword matching, reducing allocations and improving lexer throughput.

### Enhancements

- **Rework CLI and add missing normalizer option flags** ([#83](https://github.com/DataDog/go-sqllexer/pull/83))
  The `cmd/sqllexer` CLI was refactored for cleaner config plumbing and now exposes all normalizer options as flags:
  - `-keep-identifier-quotation`
  - `-dollar-quoted-func`
  - `-replace-positional-parameter`
  - `-collect-procedures`
  - `-uppercase-keywords`
  - `-remove-space-between-parentheses`
  - `-keep-trailing-semicolon`
