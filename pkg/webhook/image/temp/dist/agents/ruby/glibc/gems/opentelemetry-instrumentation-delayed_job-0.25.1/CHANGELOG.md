# Release History: opentelemetry-instrumentation-delayed_job

### v0.25.1 / 2025-10-22

* FIXED: Update opentelemetry-instrumentation-base dependency

### v0.25.0 / 2025-10-21

* BREAKING CHANGE: Min Ruby Version 3.2 and Rails 7.1

* ADDED: Min Ruby Version 3.2 and Rails 7.1

### v0.24.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.24.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.23.0 / 2025-01-16

* BREAKING CHANGE: Drop Support for EoL Rails 6.1
* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Drop Support for EoL Rails 6.1
* ADDED: Set minimum supported version to Ruby 3.1

### v0.22.4 / 2024-07-23

* DOCS: Add cspell to CI

### v0.22.3 / 2024-07-02

* DOCS: Fix CHANGELOGs to reflect a past breaking change

### v0.22.2 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.22.1 / 2023-11-23

* CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

### v0.22.0 / 2023-10-16

* BREAKING CHANGE: Drop DelayedJob ActiveRecord in Tests

* FIXED: Drop DelayedJob ActiveRecord in Tests

### v0.21.0 / 2023-09-07

* BREAKING CHANGE: Align messaging instrumentation operation names [#648](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/648)

### v0.20.1 / 2023-06-05

* FIXED: Base config options 

### v0.20.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7 

* ADDED: Drop support for EoL Ruby 2.7 

### v0.19.1 / 2023-01-14

* DOCS: Fix gem homepage 
* DOCS: More gem documentation fixes 

### v0.19.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Rails 7.0.3 test suite incompatibility 
* FIXED: Broken test file requirements 

### v0.18.5 / 2022-05-02

* FIXED: RubyGems Fallback 

### v0.18.4 / 2021-12-02

* (No significant changes)

### v0.18.3 / 2021-09-29

* (No significant changes)

### v0.18.2 / 2021-08-12

* DOCS: Update docs to rely more on environment variable configuration 

### v0.18.1 / 2021-06-23

* (No significant changes)

### v0.18.0 / 2021-05-21

* ADDED: Updated API dependency for 1.0.0.rc1
* BREAKING CHANGE: Replace Time.now with Process.clock_gettime

### v0.17.0 / 2021-04-22

* FIXED: Refactor propagators to add #fields

### v0.16.0 / 2021-03-17

* FIXED: Example scripts now reference local common lib
* DOCS: Replace Gitter with GitHub Discussions

### v0.15.0 / 2021-02-18

* (No significant changes)

### v0.14.0 / 2021-02-03

* BREAKING CHANGE: Replace getter and setter callables and remove rack specific propagators

* ADDED: Replace getter and setter callables and remove rack specific propagators

### v0.13.0 / 2021-01-29

* FIXED: Coerce message ID to string in span payload

### v0.12.0 / 2020-12-24

* (No significant changes)

### v0.11.0 / 2020-12-11

* FIXED: Copyright comments to not reference year

### v0.10.0 / 2020-12-03

* (No significant changes)

### v0.9.0 / 2020-10-07

* Initial release of Delayed Job instrumentation (ported from Datadog)
