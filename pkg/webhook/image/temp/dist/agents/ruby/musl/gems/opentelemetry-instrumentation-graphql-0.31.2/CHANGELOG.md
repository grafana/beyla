# Release History: opentelemetry-instrumentation-graphql

### v0.31.2 / 2025-10-28

* FIXED: Patch dataloader to propagate context to new fiber
* FIXED: Does not trace resolve type unless enable

### v0.31.1 / 2025-10-22

* FIXED: Update opentelemetry-instrumentation-base dependency

### v0.31.0 / 2025-10-21

* BREAKING CHANGE: Min Ruby Version 3.2 and Rails 7.1

* ADDED: Min Ruby Version 3.2 and Rails 7.1

### v0.30.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.30.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.29.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Set minimum supported version to Ruby 3.1

### v0.28.4 / 2024-07-30

* FIXED: Add super calls to GraphqlTrace

### v0.28.3 / 2024-07-23

* DOCS: Add cspell to CI

### v0.28.2 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.28.1 / 2024-04-10

* FIXED: Analyze span names in GraphQL instrumentation

### v0.28.0 / 2024-02-16

* BREAKING CHANGE: GraphQL Legacy Tracer perf improvements [#867](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/867).

* ADDED: GraphQL Legacy Tracer perf improvements [#867](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/867).

### v0.27.0 / 2023-11-28

* CHANGED: Performance optimization cache attribute hashes [#723](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/723)

### v0.26.8 / 2023-11-23

* CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

### v0.26.7 / 2023-09-27

* FIXED: Micro optimization: build Hash w/ {} (https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/665)

### v0.26.6 / 2023-08-26

* FIXED: Improve GraphQL tracing compatibility with other tracers

### v0.26.5 / 2023-08-03

* FIXED: Remove inline linter rules

### v0.26.4 / 2023-08-01

* FIXED: GraphQL tests and installation

### v0.26.3 / 2023-07-29

* FIXED: GraphQL validate events

### v0.26.2 / 2023-06-05

* FIXED: Base config options 
* FIXED: GraphQL resolve_type_lazy 

### v0.26.1 / 2023-05-30

* FIXED: GraphQL tracing

### v0.26.0 / 2023-05-17

* BREAKING CHANGE: GraphQL instrumentation: support new tracing API 

* ADDED: GraphQL instrumentation: support new tracing API

### v0.25.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7 

* ADDED: Drop support for EoL Ruby 2.7 

### v0.24.0 / 2023-03-15

* BREAKING CHANGE: Add support for GraphQL 2.0.19

* FIXED: Add support for GraphQL 2.0.19

### v0.23.0 / 2023-03-13

* BREAKING CHANGE: Lock graphql max version to 2.0.17

* FIXED: Lock graphql max version to 2.0.17

### v0.22.0 / 2023-01-27

* ADDED: Normalize GraphQL span names for easier aggregation analysis 

### v0.21.1 / 2023-01-14

* DOCS: Fix gem homepage 
* DOCS: More gem documentation fixes 

### v0.21.0 / 2022-07-12

* FIXED: Use semantic graphql attribute names 

### v0.20.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements 

### v0.19.3 / 2022-05-05

* (No significant changes)

### v0.19.2 / 2021-12-02

* (No significant changes)

### v0.19.1 / 2021-09-29

* (No significant changes)

### v0.19.0 / 2021-08-12

* ADDED: Add support for graphql errors 
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

* Initial release.
