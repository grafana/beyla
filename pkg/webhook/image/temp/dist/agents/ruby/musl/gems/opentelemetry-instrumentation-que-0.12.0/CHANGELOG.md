# Release History: opentelemetry-instrumentation-que

### v0.12.0 / 2025-12-02

* ADDED: Replace references sql-obfuscation -> sql-processor

### v0.11.1 / 2025-10-22

* FIXED: Update opentelemetry-instrumentation-base dependency

### v0.11.0 / 2025-10-21

* BREAKING CHANGE: Min Ruby Version 3.2 and Rails 7.1

* ADDED: Min Ruby Version 3.2 and Rails 7.1

### v0.10.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.10.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.9.0 / 2025-01-16

* BREAKING CHANGE: Drop Support for EoL Rails 6.1
* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Drop Support for EoL Rails 6.1
* ADDED: Set minimum supported version to Ruby 3.1

### v0.8.4 / 2024-10-08

* FIXED: Fix bulk_enqueue when enqueuing more than 5 jobs

### v0.8.3 / 2024-07-23

* DOCS: Add cspell to CI

### v0.8.2 / 2024-07-02

* DOCS: Fix CHANGELOGs to reflect a past breaking change

### v0.8.1 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.8.0 / 2024-02-08

* BREAKING CHANGE: Move shared sql behavior to helper gems


### v0.7.1 / 2023-11-23

* CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

### v0.7.0 / 2023-09-07

* BREAKING CHANGE: Align messaging instrumentation operation names [#648](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/648)

### v0.6.2 / 2023-08-07

* FIXED: Correctly set bulk_enqueue job options

### v0.6.1 / 2023-06-05

* FIXED: Base config options 

### v0.6.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7 

* ADDED: Drop support for EoL Ruby 2.7 
* FIXED: Drop Rails dependency for ActiveSupport Instrumentation 

### v0.5.1 / 2023-01-14

* FIXED: Remove `job_options` when using `bulk_enqueue` 
* DOCS: Fix gem homepage 
* DOCS: More gem documentation fixes 

### v0.5.0 / 2022-10-28

* ADDED: Add support for `job_options` argument

### v0.4.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements 

### v0.3.0 / 2022-05-02

* ADDED: Validate Using Enums 
* FIXED: RubyGems Fallback 

### v0.2.0 / 2021-12-01

* ADDED: Instrument Que poller 

### v0.1.1 / 2021-09-29

* (No significant changes)

### v0.1.0 / 2021-09-15

* Initial release.
