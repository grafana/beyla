# Release History: opentelemetry-instrumentation-active_job

## v0.13.0 / 2026-06-16

- ADDED: Add spans for Continuation (#2361)
- ADDED: Add step.active_job span handler for Continuation

## v0.12.0 / 2026-04-28

- BREAKING CHANGE: Min Rails 7.1 (enforced this time) (#2283)
- ADDED: Min Rails 7.1 (enforced this time) (#2283)

## v0.11.0 / 2026-04-14

- BREAKING CHANGE: Min Ruby Version 3.3 (#2125)
- ADDED: Min Ruby Version 3.3 (#2125)
- ADDED: Add release tag into source code url of gem metadata (#1984)

## v0.10.1 / 2025-10-22

- FIXED: Update opentelemetry-instrumentation-base dependency

## v0.10.0 / 2025-10-21

- BREAKING CHANGE: Min Ruby Version 3.2 and Rails 7.1
- ADDED: Min Ruby Version 3.2 and Rails 7.1

## v0.9.2 / 2025-10-07

- DOCS: Enhance README

## v0.9.1 / 2025-09-30

- FIXED: Min OTel Ruby API 1.7

## v0.9.0 / 2025-09-30

- ADDED: Bump minimum API Version to 1.7

## v0.8.0 / 2025-01-16

- BREAKING CHANGE: Drop Support for EoL Rails 6.1
- BREAKING CHANGE: Set minimum supported version to Ruby 3.1
- ADDED: Drop Support for EoL Rails 6.1
- ADDED: Set minimum supported version to Ruby 3.1

## v0.7.8 / 2024-10-24

- FIXED: ActiveJob Propagate baggage information properly when performing

## v0.7.7 / 2024-08-21

- FIXED: Propagate context between enqueue and perform

## v0.7.6 / 2024-08-15

- FIXED: Prefix ::ActiveSupport when installing the instrumentation

## v0.7.5 / 2024-08-15

- FIXED: Use Active Support Lazy Load Hooks to avoid prematurely initializing ActiveRecord::Base and ActiveJob::Base

## v0.7.4 / 2024-07-30

- FIXED: Honour dynamic changes in configuration

## v0.7.3 / 2024-07-22

- FIXED: ActiveJob::Handlers.unsubscribe

## v0.7.2 / 2024-07-02

- DOCS: Fix CHANGELOGs to reflect a past breaking change

## v0.7.1 / 2023-11-23

- CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

## v0.7.0 / 2023-11-22

- BREAKING CHANGE: Drop Rails 6.0 EOL
- ADDED: Drop Rails 6.0 EOL
- BREAKING CHANGE: Use ActiveSupport Instrumentation instead of Monkey Patches
- CHANGED: Use ActiveSupport Instrumentation instead of Monkey Patches [#677](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/677)

## v0.6.1 / 2023-10-16

- FIXED: Add Rails 7.1 compatibility

## v0.6.0 / 2023-09-07

- BREAKING CHANGE: Align messaging instrumentation operation names [#648](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/648)

## v0.5.2 / 2023-08-03

- FIXED: Add code semconv attributes
- FIXED: Remove inline linter rules

## v0.5.1 / 2023-06-05

- FIXED: Base config options

## v0.5.0 / 2023-04-17

- BREAKING CHANGE: Drop support for EoL Ruby 2.7
- ADDED: Drop support for EoL Ruby 2.7

## v0.4.0 / 2023-02-01

- BREAKING CHANGE: Drop Rails 5 Support
- ADDED: Drop Rails 5 Support

## v0.3.1 / 2023-01-14

- DOCS: Fix gem homepage
- DOCS: More gem documentation fixes

## v0.3.0 / 2022-06-09

- Upgrading Base dependency version
- FIXED: Broken test file requirements

## v0.2.0 / 2022-05-02

- ADDED: Validate Using Enums
- ADDED: Make the context available in ActiveJob notifications
- FIXED: Fix deserialization of jobs that are missing metadata
- FIXED: RubyGems Fallback

## v0.1.5 / 2021-12-02

- (No significant changes)

## v0.1.4 / 2021-09-29

- (No significant changes)

## v0.1.3 / 2021-08-12

- (No significant changes)

## v0.1.2 / 2021-07-01

- FIXED: Support Active Jobs with keyword args across ruby versions

## v0.1.1 / 2021-06-29

- FIXED: Compatibility with RC2 span status api changes [845](https://github.com/open-telemetry/opentelemetry-ruby/pull/845)

## v0.1.0 / 2021-06-23

- Initial release.
