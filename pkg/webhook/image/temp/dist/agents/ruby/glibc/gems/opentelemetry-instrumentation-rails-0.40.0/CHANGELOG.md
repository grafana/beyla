# Release History: opentelemetry-instrumentation-rails

### v0.40.0 / 2026-03-17

* BREAKING CHANGE: Default to stable HTTP semantic conventions (#2051)
* ADDED: Default to stable HTTP semantic conventions (#2051)

### v0.39.1 / 2025-10-22

* FIXED: Update opentelemetry-instrumentation-base dependency

### v0.39.0 / 2025-10-21

* BREAKING CHANGE: Min Ruby Version 3.2 and Rails 7.1
* ADDED: Min Ruby Version 3.2 and Rails 7.1

### v0.38.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.37.0 / 2025-08-19

ADDED: Add action_pack `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable compatibility for Rack integration [#1594](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1594)

### v0.36.0 / 2025-02-04

* ADDED: Add active_storage instrumentation to `rails`
* ADDED: Strip Rails `(.:format)` suffix from `http.route` (action_pack)

### v0.35.1 / 2025-01-28

* DOCS: Required version in Rails README from 0.24 to 0.34.

### v0.35.0 / 2025-01-16

* BREAKING CHANGE: Drop Support for EoL Rails 6.1
* BREAKING CHANGE: Set minimum supported version to Ruby 3.1
* ADDED: Drop Support for EoL Rails 6.1
* ADDED: Set minimum supported version to Ruby 3.1

### v0.34.1 / 2025-01-14

* FIXED: Add Concurrent Ruby dependency to Rails

### v0.34.0 / 2024-12-19

* ADDED: Upgrade ActiveSupport Instrumentation 0.7.0

### v0.33.1 / 2024-11-26

* (No significant changes)

### v0.33.0 / 2024-11-19

* ADDED: Use Semconv Naming For ActionPack

### v0.32.0 / 2024-10-22

* BREAKING CHANGE: Rename Active Record find_by_sql spans to query
* FIXED: Emit Active Record query spans for Rails 7.0+
* ADDED: Subscribe to process.action_mailer notifications

### v0.31.2 / 2024-08-15

* FIXED: Rails instrumentation should load ActiveJob instrumentation

### v0.31.1 / 2024-07-23

* DOCS: Add cspell to CI

### v0.31.0 / 2024-07-02

* DOCS: Fix CHANGELOGs to reflect a past breaking change
* CHANGED: Update ActiveSupport Instrumentation

### v0.30.2 / 2024-06-04

* FIXED: Add action_mailer to rails and all

### v0.30.1 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.30.0 / 2024-01-09

* BREAKING CHANGE: Use ActiveSupport instead of patches #703

### v0.29.1 / 2023-11-23

* CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

### v0.29.0 / 2023-11-22

* BREAKING CHANGE: Drop Rails 6.0 EOL
* ADDED: Drop Rails 6.0 EOL

### v0.28.1 / 2023-10-16

* FIXED: Add Rails 7.1 compatibility

### v0.28.0 / 2023-09-07

* BREAKING CHANGE: Align messaging instrumentation operation names [#648](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/648)

### v0.27.1 / 2023-06-05

* FIXED: Use latest bug fix version for all dependencies

### v0.27.0 / 2023-06-05

* FIXED: Base config options
* FIXED: Upgrade ActionPack and ActionView min versions

### v0.26.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7
* ADDED: Drop support for EoL Ruby 2.7

### v0.25.0 / 2023-02-08

* BREAKING CHANGE: Update Instrumentations GraphQL, HttpClient, Rails [#303](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/303)
* BREAKING CHANGE: Drop Rails 5 Support [#315](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/315)
* DOCS: Rails Instrumentation Compatibility

### v0.24.1 / 2023-01-14

* DOCS: Fix gem homepage

### v0.24.0 / 2022-12-06

* BREAKING CHANGE: Remove enable_recognize_route and span_naming options
* FIXED: Remove enable_recognize_route and span_naming options

### v0.23.1 / 2022-11-08

* FIXED: Bump rails instrumentation dependency on action_pack instrumentation

### v0.23.0 / 2022-10-14

* ADDED: Name ActionPack spans with the HTTP method and route

### v0.22.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements

### v0.21.0 / 2022-05-02

* ADDED: OTel Railtie
* FIXED: RubyGems Fallback

### v0.20.0 / 2021-12-01

* ADDED: Move activesupport notification subscriber out of action_view gem
* FIXED: Instrumentation of Rails 7

### v0.19.4 / 2021-10-06

* (No significant changes)

### v0.19.3 / 2021-09-29

* (No significant changes)

### v0.19.2 / 2021-09-29

* (No significant changes)

### v0.19.1 / 2021-09-09

* (No significant changes)

### v0.19.0 / 2021-08-12

* ADDED: Instrument active record
* ADDED: Add ActionView instrumentation via ActiveSupport::Notifications
* FIXED: Rails instrumentation to not explicitly install sub gems
* DOCS: Update docs to rely more on environment variable configuration
* This release adds support for Active Record and Action View.
* The `enable_recognize_route` configuration option has been moved to the ActionPack gem.
* See readme for details on how to configure the sub instrumentation gems.

### v0.18.1 / 2021-06-23

* FIXED: Updated rack middleware position to zero

### v0.18.0 / 2021-05-21

* ADDED: Updated API dependency for 1.0.0.rc1

### v0.17.0 / 2021-04-22

* ADDED: Added http.route in rails instrumentation to match the spec
* FIXED: Rails example by not using `rails` from git
* FIXED: Updated rack middleware position to zero

### v0.16.0 / 2021-03-17

* FIXED: Example scripts now reference local common lib
* DOCS: Replace Gitter with GitHub Discussions

### v0.15.0 / 2021-02-18

* (No significant changes)

### v0.14.0 / 2021-02-03

* (No significant changes)

### v0.13.0 / 2021-01-29

* (No significant changes)

### v0.12.0 / 2020-12-24

* (No significant changes)

### v0.11.0 / 2020-12-11

* FIXED: Rails tests
* FIXED: Copyright comments to not reference year

### v0.10.0 / 2020-12-03

* FIXED: Otel-instrumentation-all not installing all

### v0.9.0 / 2020-11-27

* Initial release.
