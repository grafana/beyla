# Release History: opentelemetry-instrumentation-redis

### v0.28.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2

* ADDED: Min Ruby Version 3.2

### v0.27.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.27.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.26.1 / 2025-02-04

* FIXED: Do not expose auth params with Redis 5

### v0.26.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Set minimum supported version to Ruby 3.1

### v0.25.7 / 2024-07-23

* DOCS: Add cspell to CI

### v0.25.6 / 2024-06-18

* FIXED: Relax otel common gem constraints

### v0.25.5 / 2024-05-09

* FIXED: Untrace entire request

### v0.25.4 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.25.3 / 2023-08-03

* FIXED: Remove inline linter rules

### v0.25.2 / 2023-07-21

* ADDED: Update `opentelemetry-common` from [0.19.3 to 0.20.0](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/537)

### v0.25.1 / 2023-06-05

* FIXED: Base config options 

### v0.25.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7 

* ADDED: Drop support for EoL Ruby 2.7 

### v0.24.1 / 2023-01-14

* DOCS: Fix gem homepage 
* DOCS: More gem documentation fixes 

### v0.24.0 / 2022-09-14

* ADDED: Redis-rb 5.0 and redis-client support 

### v0.23.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements 

### v0.22.1 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements 

### v0.22.0 / 2022-05-02

* ADDED: Validate Using Enums 
* FIXED: Add appraisals for redis 4.2-4.6 

### v0.21.3 / 2022-02-02

* FIXED: Prevent redis instrumentation from mutating the command 

### v0.21.2 / 2021-12-01

* (No significant changes)

### v0.21.1 / 2021-09-29

* (No significant changes)

### v0.21.0 / 2021-08-12

* ADDED: Add toggle for redis db.statement attribute 

### v0.20.0 / 2021-06-23

* BREAKING CHANGE: Total order constraint on span.status= 

* FIXED: Total order constraint on span.status= 

### v0.19.0 / 2021-05-28

* ADDED: Configuration option to enable or disable redis root spans [#777](https://github.com/open-telemetry/opentelemetry-ruby/pull/777)

### v0.18.0 / 2021-05-21

* ADDED: Updated API dependency for 1.0.0.rc1
refactor: redis attribute utils [#760](https://github.com/open-telemetry/opentelemetry-ruby/pull/760)
refactor: simplify redis attribute assignment [#758](https://github.com/open-telemetry/opentelemetry-ruby/pull/758)
test: split redis instrumentation test [#754](https://github.com/open-telemetry/opentelemetry-ruby/pull/754)
* ADDED: Option to obfuscate redis arguments
* FIXED: Instrument Redis more thoroughly by patching Client#process.

### v0.17.0 / 2021-04-22

* (No significant changes)

### v0.16.0 / 2021-03-17

* FIXED: Update DB semantic conventions
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

* ADDED: Accept config for redis peer service attribute
* ADDED: Move utf8 encoding to common utils
* FIXED: Copyright comments to not reference year

### v0.10.1 / 2020-12-09

* FIXED: Semantic conventions db.type -> db.system

### v0.10.0 / 2020-12-03

* (No significant changes)

### v0.9.0 / 2020-11-27

* BREAKING CHANGE: Add timeout for force_flush and shutdown

* ADDED: Redis attribute propagation
* ADDED: Add timeout for force_flush and shutdown

### v0.8.0 / 2020-10-27

* BREAKING CHANGE: Remove 'canonical' from status codes

* FIXED: Remove 'canonical' from status codes

### v0.7.0 / 2020-10-07

* DOCS: Added redis documentation
* DOCS: Standardize top-level docs structure and readme

### v0.6.0 / 2020-09-10

* (No significant changes)
