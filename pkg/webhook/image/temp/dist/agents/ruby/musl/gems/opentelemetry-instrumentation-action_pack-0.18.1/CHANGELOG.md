# Release History: opentelemetry-instrumentation-action_pack

## v0.18.1 / 2026-08-18

- FIXED: Prepend engine mount path to http.route for mounted Rails engines (#2499)

## v0.18.0 / 2026-04-28

- BREAKING CHANGE: Min Rails 7.1 (enforced this time) (#2283)
- ADDED: Min Rails 7.1 (enforced this time) (#2283)

## v0.17.0 / 2026-04-14

- BREAKING CHANGE: Min Ruby Version 3.3 (#2125)
- ADDED: Min Ruby Version 3.3 (#2125)
- ADDED: Add release tag into source code url of gem metadata (#1984)

## v0.16.0 / 2026-03-17

- BREAKING CHANGE: Default to stable HTTP semantic conventions (#2051)
- ADDED: Default to stable HTTP semantic conventions (#2051)

## v0.15.1 / 2025-10-22

- FIXED: Update opentelemetry-instrumentation-base dependency

## v0.15.0 / 2025-10-21

- BREAKING CHANGE: Min Ruby Version 3.2 and Rails 7.1
- ADDED: Min Ruby Version 3.2 and Rails 7.1

## v0.14.1 / 2025-10-07

- FIXED: Unify rack middleware_args

## v0.14.0 / 2025-09-30

- ADDED: Bump minimum API Version to 1.7

## v0.13.0 / 2025-08-19

- ADDED: Add `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable compatibility for Rack integration [#1594](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1594)

## v0.12.3 / 2025-06-16

- FIXED: Action_pack always assuming sdk spans

## v0.12.2 / 2025-06-04

- FIXED: Rack span class naming

## v0.12.1 / 2025-05-07

- FIXED: Account for `nil` routes

## v0.12.0 / 2025-02-04

- ADDED: Strip Rails `(.:format)` suffix from `http.route`

## v0.11.0 / 2025-01-16

- BREAKING CHANGE: Drop Support for EoL Rails 6.1
- BREAKING CHANGE: Set minimum supported version to Ruby 3.1
- ADDED: Drop Support for EoL Rails 6.1
- ADDED: Set minimum supported version to Ruby 3.1

## v0.10.0 / 2024-11-19

- ADDED: Use Semconv Naming For ActionPack

## v0.9.0 / 2024-01-09

- BREAKING CHANGE: Use ActiveSupport instead of patches #703

## v0.8.0 / 2023-11-22

- BREAKING CHANGE: Drop Rails 6.0 EOL
- ADDED: Drop Rails 6.0 EOL

## v0.7.1 / 2023-10-16

- FIXED: Add Rails 7.1 compatibility

## v0.7.0 / 2023-06-05

- ADDED: Use Rack Middleware Helper
- FIXED: Base config options

## v0.6.0 / 2023-04-17

- BREAKING CHANGE: Drop support for EoL Ruby 2.7
- ADDED: Drop support for EoL Ruby 2.7

## v0.5.0 / 2023-02-01

- BREAKING CHANGE: Drop Rails 5 Support
- ADDED: Drop Rails 5 Support
- FIXED: Drop Rails dependency for ActiveSupport Instrumentation

## v0.4.1 / 2023-01-14

- FIXED: String-ify code.function Span attribute
- DOCS: Fix gem homepage
- DOCS: More gem documentation fixes

## v0.4.0 / 2022-12-06

- BREAKING CHANGE: Remove enable_recognize_route and span_naming options
- FIXED: Remove enable_recognize_route and span_naming options

## v0.3.2 / 2022-11-16

- FIXED: Loosen dependency on Rack

## v0.3.1 / 2022-10-27

- FIXED: Declare span_naming option in action_pack instrumentation

## v0.3.0 / 2022-10-14

- ADDED: Name ActionPack spans with the HTTP method and route

## v0.2.1 / 2022-10-04

- FIXED: Ensures the correct route is add to http.route span attribute

## v0.2.0 / 2022-06-09

- Upgrading Base dependency version
- FIXED: Broken test file requirements

## v0.1.4 / 2022-05-02

- FIXED: Use rails request's filtered path as http.target attribute
- FIXED: RubyGems Fallback

## v0.1.3 / 2021-12-01

- FIXED: Instrumentation of Rails 7

## v0.1.2 / 2021-10-06

- FIXED: Prevent high cardinality rack span name as a default

## v0.1.1 / 2021-09-29

- (No significant changes)

## v0.1.0 / 2021-08-12

- Initial release.
