# Release History: opentelemetry-instrumentation-mysql2

### v0.33.0 / 2026-01-13

* ADDED: Add SQL Comment Propagator

### v0.32.1 / 2025-12-03

* FIXED: Update gemspec dependencies to sql-processor

### v0.32.0 / 2025-12-02

* ADDED: Replace references sql-obfuscation -> sql-processor

### v0.31.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2

* ADDED: Min Ruby Version 3.2

### v0.30.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.30.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.29.1 / 2025-04-16

* refactor: Use SQL helpers for context attributes #1271

### v0.29.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Set minimum supported version to Ruby 3.1

### v0.28.0 / 2024-09-12

- BREAKING CHANGE: Return message when sql is over the obfuscation limit. Fixes a bug where sql statements with prepended comments that hit the obfuscation limit would be sent raw.

### v0.27.2 / 2024-07-23

- DOCS: Add cspell to CI

### v0.27.1 / 2024-04-30

- FIXED: Bundler conflict warnings

### v0.27.0 / 2024-02-15

- ADDED: Instrument mysql2 prepare statement

### v0.26.1 / 2024-02-08

- FIXED: Add missing requires for sql-helpers to mysql, pg, and trilogy instrumentation

### v0.26.0 / 2024-02-08

- BREAKING CHANGE: Move shared sql behavior to helper gems

### v0.25.0 / 2023-10-16

- BREAKING CHANGE: Obfuscation for mysql2, dalli and postgresql as default option for db_statement

- ADDED: Obfuscation for mysql2, dalli and postgresql as default option for db_statement

### v0.24.3 / 2023-08-03

- FIXED: Remove inline linter rules

### v0.24.2 / 2023-06-05

- FIXED: Base config options

### v0.24.1 / 2023-06-01

- FIXED: Regex non-match with obfuscation limit (issue #486)

### v0.24.0 / 2023-05-25

- ADDED: Add config[:obfuscation_limit] to pg and mysql2

### v0.23.0 / 2023-04-17

- BREAKING CHANGE: Drop support for EoL Ruby 2.7

- ADDED: Drop support for EoL Ruby 2.7
- FIXED: Ensure encoding errors handled during SQL obfuscation for Trilogy

### v0.22.0 / 2023-01-14

- BREAKING CHANGE: Removed deprecated instrumentation options

- ADDED: Add option to configure span name
- ADDED: Removed deprecated instrumentation options
- DOCS: Fix gem homepage
- DOCS: More gem documentation fixes

### v0.21.1 / 2022-10-26

- FIXED: Handle encoding errors in mysql obfuscation

### v0.21.0 / 2022-06-09

- Upgrading Base dependency version
- FIXED: Broken test file requirements

### v0.20.1 / 2022-05-03

- ADDED: `with_attributes` method for context propagation

### v0.20.0 / 2021-12-01

- ADDED: Add default options config helper + env var config option support

### v0.19.1 / 2021-09-29

- (No significant changes)

### v0.19.0 / 2021-08-12

- BREAKING CHANGE: Add option for db.statement

- ADDED: Add option for db.statement
- DOCS: Update docs to rely more on environment variable configuration
- DOCS: Move to using new db_statement

### v0.18.1 / 2021-06-23

- (No significant changes)

### v0.18.0 / 2021-05-21

- ADDED: Updated API dependency for 1.0.0.rc1
- Fix: Nil value for db.name attribute #744

### v0.17.0 / 2021-04-22

- (No significant changes)

### v0.16.0 / 2021-03-17

- FIXED: Update DB semantic conventions
- FIXED: Example scripts now reference local common lib
- ADDED: Configurable obfuscation of sql in mysql2 instrumentation to avoid logging sensitive data

### v0.15.0 / 2021-02-18

- ADDED: Add instrumentation config validation

### v0.14.0 / 2021-02-03

- (No significant changes)

### v0.13.0 / 2021-01-29

- (No significant changes)

### v0.12.0 / 2020-12-24

- (No significant changes)

### v0.11.0 / 2020-12-11

- ADDED: Add peer service config to mysql
- FIXED: Copyright comments to not reference year

### v0.10.1 / 2020-12-09

- FIXED: Semantic conventions db.type -> db.system

### v0.10.0 / 2020-12-03

- (No significant changes)

### v0.9.0 / 2020-11-27

- BREAKING CHANGE: Add timeout for force_flush and shutdown

- ADDED: Add timeout for force_flush and shutdown

### v0.8.0 / 2020-10-27

- BREAKING CHANGE: Remove 'canonical' from status codes

- FIXED: Remove 'canonical' from status codes

### v0.7.0 / 2020-10-07

- DOCS: Standardize top-level docs structure and readme

### v0.6.0 / 2020-09-10

- (No significant changes)
