# Release History: opentelemetry-instrumentation-dalli

### v0.29.2 / 2026-02-27

* FIXED: Replace return with implicit block value in compatible block (#2029)

### v0.29.1 / 2026-02-24

* FIXED: Skip instrumenting dalli 4.2.0 (#1982)

### v0.29.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2
* ADDED: Min Ruby Version 3.2

### v0.28.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.28.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.27.3 / 2025-05-27

* FIXED: Compact Dalli attributes

### v0.27.2 / 2025-04-30

* FIXED: Do not pollute the `OpenTelemetry::Instrumentation` namespace

### v0.27.1 / 2025-04-21

* FIXED: Only prepend Dalli patch if binary protocol defined

### v0.27.0 / 2025-04-15

* ADDED: Support meta protocol instrumentation

### v0.26.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1
* ADDED: Set minimum supported version to Ruby 3.1
* FIXED: Format gat commands

### v0.25.4 / 2024-07-23

* DOCS: Add cspell to CI

### v0.25.3 / 2024-06-18

* FIXED: Relax otel common gem constraints

### v0.25.2 / 2024-05-09

* FIXED: Untrace entire request

### v0.25.1 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.25.0 / 2023-10-16

* BREAKING CHANGE: Obfuscation for mysql2, dalli and postgresql as default option for db_statement
* ADDED: Obfuscation for mysql2, dalli and postgresql as default option for db_statement

### v0.24.2 / 2023-07-21

* ADDED: Update `opentelemetry-common` from [0.19.3 to 0.20.0](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/537)

### v0.24.1 / 2023-06-05

* FIXED: Base config options

### v0.24.0 / 2023-05-15

* ADDED: Add db.operation attribute for dalli

### v0.23.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7
* ADDED: Drop support for EoL Ruby 2.7

### v0.22.2 / 2023-01-14

* DOCS: Fix gem homepage
* DOCS: More gem documentation fixes

### v0.22.1 / 2022-11-28

* FIXED: `format_command`'s terrible performance

### v0.22.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements

### v0.21.0 / 2022-05-02

* ADDED: Validate Using Enums

### v0.20.0 / 2021-12-01

* ADDED: Add dalli obfuscation for db_statement
* FIXED: Resolve Dalli::Server deprecation in 3.0+

### v0.19.1 / 2021-09-29

* (No significant changes)

### v0.19.0 / 2021-08-12

* ADDED: Add configuration options for dalli
* DOCS: Update docs to rely more on environment variable configuration

### v0.18.1 / 2021-06-23

* (No significant changes)

### v0.18.0 / 2021-05-21

* ADDED: Updated API dependency for 1.0.0.rc1

### v0.17.0 / 2021-04-22

* (No significant changes)

### v0.16.0 / 2021-03-17

* FIXED: Example scripts now reference local common lib
* DOCS: Replace Gitter with GitHub Discussions

### v0.15.0 / 2021-02-18

* ADDED: Add instrumentation config validation

### v0.14.0 / 2021-02-03

* (No significant changes)

### v0.13.0 / 2021-01-29

* (No significant changes)

### v0.12.0 / 2020-12-24

* (No significant changes)

### v0.11.0 / 2020-12-11

* ADDED: Add peer service config to dalli
* ADDED: Move utf8 encoding to common utils
* FIXED: Copyright comments to not reference year

### v0.10.0 / 2020-12-03

* (No significant changes)

### v0.9.0 / 2020-11-27

* BREAKING CHANGE: Add timeout for force_flush and shutdown
* ADDED: Add timeout for force_flush and shutdown

### v0.8.0 / 2020-10-27

* (No significant changes)

### v0.7.0 / 2020-10-07

* DOCS: Standardize top-level docs structure and readme

### v0.6.0 / 2020-09-10

* Initial release.
