# Release History: opentelemetry-instrumentation-pg

### v0.35.0 / 2026-01-13

* ADDED: Add SQL Comment Propagator

### v0.34.1 / 2025-12-03

* FIXED: Update gemspec dependencies to sql-processor

### v0.34.0 / 2025-12-02

* ADDED: Replace references sql-obfuscation -> sql-processor

### v0.33.0 / 2025-11-03

* ADDED: Instrument PG connect

### v0.32.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2

* ADDED: Min Ruby Version 3.2

### v0.31.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.31.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.30.1 / 2025-04-16

* refactor: Use SQL helpers for context attributes #1271

### v0.30.0 / 2025-01-16

* BREAKING CHANGE: Drop Support for EoL Rails 6.1
* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Drop Support for EoL Rails 6.1
* ADDED: Set minimum supported version to Ruby 3.1

### v0.29.2 / 2025-01-07

* FIXED: Update instrumentation pg to support merge statements

### v0.29.1 / 2024-11-26

* FIXED: Get correct table name if table name is quoted

### v0.29.0 / 2024-09-12

- BREAKING CHANGE: Return message when sql is over the obfuscation limit. Fixes a bug where sql statements with prepended comments that hit the obfuscation limit would be sent raw.

### v0.28.0 / 2024-08-15

- ADDED: Collect pg db.collection_name attribute
- FIXED: Update versions to be tested (includes drop support for pg 1.2)

### v0.27.4 / 2024-07-23

- DOCS: Add cspell to CI

### v0.27.3 / 2024-05-11

- ADDED: Support prepend SQL comment for PG instrumentation

### v0.27.2 / 2024-04-30

- FIXED: Bundler conflict warnings

### v0.27.1 / 2024-02-08

- FIXED: Add missing requires for sql-helpers to mysql, pg, and trilogy instrumentation

### v0.27.0 / 2024-02-08

- BREAKING CHANGE: Move shared sql behavior to helper gems

### v0.26.1 / 2023-11-23

- CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

### v0.26.0 / 2023-10-16

- BREAKING CHANGE: Obfuscation for mysql2, dalli and postgresql as default option for db_statement

- ADDED: Obfuscation for mysql2, dalli and postgresql as default option for db_statement

### v0.25.3 / 2023-07-29

- FIXED: Pass block explicitly in `define_method` calls for PG instrumentation query methods

### v0.25.2 / 2023-06-05

- FIXED: Base config options

### v0.25.1 / 2023-06-01

- FIXED: Regex non-match with obfuscation limit (issue #486)

### v0.25.0 / 2023-05-25

- ADDED: Add config[:obfuscation_limit] to pg and mysql2

### v0.24.0 / 2023-04-17

- BREAKING CHANGE: Drop support for EoL Ruby 2.7

- ADDED: Drop support for EoL Ruby 2.7

### v0.23.0 / 2023-01-14

- BREAKING CHANGE: Removed deprecated instrumentation options

- ADDED: Removed deprecated instrumentation options
- FIXED: Reduce Hash Allocations in PG Instrumentation
- DOCS: Fix gem homepage
- DOCS: More gem documentation fixes

### v0.22.3 / 2022-12-06

- FIXED: Use attributes from the active PG connection

### v0.22.2 / 2022-11-10

- FIXED: Safeguard against host being nil

### v0.22.1 / 2022-10-27

- FIXED: Only take the first item in a comma-separated list for pg attrs

### v0.22.0 / 2022-10-04

- ADDED: Add `with_attributes` context propagation for PG instrumentation

### v0.21.0 / 2022-06-09

- Upgrading Base dependency version
- FIXED: Broken test file requirements

### v0.20.0 / 2022-05-02

- ADDED: Validate Using Enums
- FIXED: Update pg instrumentation to handle non primitive argument
- FIXED: RubyGems Fallback

### v0.19.2 / 2021-12-02

- (No significant changes)

### v0.19.1 / 2021-09-29

- (No significant changes)

### v0.19.0 / 2021-08-12

- ADDED: Add db_statement toggle for postgres
- DOCS: Update docs to rely more on environment variable configuration

### v0.18.1 / 2021-06-23

- (No significant changes)

### v0.18.0 / 2021-05-21

- ADDED: Updated API dependency for 1.0.0.rc1
- ADDED: Add option to postgres instrumentation to disable db.statement

### v0.17.1 / 2021-04-23

- Initial release.
- ADDED: Initial postgresql instrumentation
