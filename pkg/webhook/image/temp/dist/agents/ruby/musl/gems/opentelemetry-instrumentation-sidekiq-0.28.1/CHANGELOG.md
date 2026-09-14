# Release History: opentelemetry-instrumentation-sidekiq

### v0.28.1 / 2025-12-02

* FIXED: Sidekiq spans crashing when enqueued by Exq

### v0.28.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2

* ADDED: Min Ruby Version 3.2

### v0.27.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.27.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.26.1 / 2025-04-01

* FIXED: Add support for Sidekiq 8

### v0.26.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Set minimum supported version to Ruby 3.1

### v0.25.7 / 2024-07-23

* DOCS: Add cspell to CI

### v0.25.6 / 2024-07-02

* DOCS: Fix CHANGELOGs to reflect a past breaking change

### v0.25.5 / 2024-06-18

* FIXED: Relax otel common gem constraints

### v0.25.4 / 2024-05-09

* FIXED: Untrace entire request

### v0.25.3 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.25.2 / 2024-02-08

* DOCS: Fix doc for sidekiq options.

### v0.25.1 / 2024-02-08

* DOCS: ✏️ Sidekiq instrumentation options

### v0.25.0 / 2023-09-07

* BREAKING CHANGE: Align messaging instrumentation operation names [#648](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/648)
*
### v0.24.4 / 2023-08-07

* FIXED: Allow traces inside jobs while avoiding Redis noise

### v0.24.3 / 2023-08-03

* FIXED: Remove inline linter rules

### v0.24.2 / 2023-07-21

* ADDED: Update `opentelemetry-common` from [0.19.3 to 0.20.0](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/537)

### v0.24.1 / 2023-06-05

* FIXED: Base config options 

### v0.24.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7 

* ADDED: Drop support for EoL Ruby 2.7 

### v0.23.0 / 2023-02-01

* BREAKING CHANGE: Drop Rails 5 Support 

* ADDED: Drop Rails 5 Support 

### v0.22.1 / 2023-01-14

* DOCS: Fix gem homepage 
* DOCS: More gem documentation fixes 

### v0.22.0 / 2022-06-09

* Upgrading Base dependency version

### v0.21.1 / 2022-06-09

* FIXED: Broken test file requirements 
* FIXED: Make sidekiq instrumentation compatible with sidekiq 6.5.0 

### v0.21.0 / 2022-05-02

* ADDED: Validate Using Enums 
* FIXED: RubyGems Fallback 

### v0.20.2 / 2021-12-02

* (No significant changes)

### v0.20.1 / 2021-09-29

* (No significant changes)

### v0.20.0 / 2021-08-18

* ADDED: Gracefully flush provider on sidekiq shutdown event 

### v0.19.1 / 2021-08-12

* (No significant changes)

### v0.19.0 / 2021-06-23

* BREAKING CHANGE: Sidekiq propagation config 
  - Config option enable_job_class_span_names renamed to span_naming and now expects a symbol of value :job_class, or :queue
  - The default behaviour is no longer to have one continuous trace for the enqueue and process spans, using links is the new default.  To maintain the previous behaviour the config option propagation_style must be set to :child.
* BREAKING CHANGE: Total order constraint on span.status= 

* FIXED: Sidekiq propagation config 
* FIXED: Total order constraint on span.status= 

### v0.18.0 / 2021-05-21

* ADDED: Updated API dependency for 1.0.0.rc1
* TEST: update test for redis instrumentation refactor [#760](https://github.com/open-telemetry/opentelemetry-ruby/pull/760)
* BREAKING CHANGE: Remove optional parent_context from in_span

* FIXED: Remove optional parent_context from in_span
* FIXED: Instrument Redis more thoroughly by patching Client#process.

### v0.17.0 / 2021-04-22

* ADDED: Accept config for sidekiq peer service attribute

### v0.16.0 / 2021-03-17

* FIXED: Example scripts now reference local common lib
* DOCS: Replace Gitter with GitHub Discussions

### v0.15.0 / 2021-02-18

* ADDED: Add instrumentation config validation

### v0.14.0 / 2021-02-03

* BREAKING CHANGE: Replace getter and setter callables and remove rack specific propagators

* ADDED: Replace getter and setter callables and remove rack specific propagators

### v0.13.0 / 2021-01-29

* ADDED: Instrument sidekiq background work
* FIXED: Adjust Sidekiq middlewares to match semantic conventions
* FIXED: Set minimum compatible version and use untraced helper

### v0.12.0 / 2020-12-24

* (No significant changes)

### v0.11.0 / 2020-12-11

* FIXED: Copyright comments to not reference year

### v0.10.0 / 2020-12-03

* (No significant changes)

### v0.9.0 / 2020-11-27

* BREAKING CHANGE: Add timeout for force_flush and shutdown

* ADDED: Add timeout for force_flush and shutdown

### v0.8.0 / 2020-10-27

* (No significant changes)

### v0.7.0 / 2020-10-07

* DOCS: Adding README for Sidekiq instrumentation
* DOCS: Remove duplicate reference in Sidekiq README
* DOCS: Standardize top-level docs structure and readme

### v0.6.0 / 2020-09-10

* (No significant changes)
