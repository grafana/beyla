# Release History: opentelemetry-instrumentation-active_record

## v0.13.0 / 2026-04-28

- BREAKING CHANGE: Min Rails 7.1 (enforced this time) (#2283)
- ADDED: Min Rails 7.1 (enforced this time) (#2283)

## v0.12.0 / 2026-04-14

- BREAKING CHANGE: Min Ruby Version 3.3 (#2125)
- ADDED: Min Ruby Version 3.3 (#2125)
- ADDED: Add release tag into source code url of gem metadata (#1984)

## v0.11.1 / 2025-10-22

- FIXED: Update opentelemetry-instrumentation-base dependency

## v0.11.0 / 2025-10-21

- BREAKING CHANGE: Min Ruby Version 3.2 and Rails 7.1
- ADDED: Min Ruby Version 3.2 and Rails 7.1

## v0.10.1 / 2025-09-30

- FIXED: Min OTel Ruby API 1.7

## v0.10.0 / 2025-09-30

- ADDED: Bump minimum API Version to 1.7

## v0.9.0 / 2025-01-16

- BREAKING CHANGE: Drop Support for EoL Rails 6.1
- BREAKING CHANGE: Set minimum supported version to Ruby 3.1
- ADDED: Drop Support for EoL Rails 6.1
- ADDED: Set minimum supported version to Ruby 3.1

## v0.8.1 / 2024-11-21

- FIXED: Pass block argument in ActiveRecord `find_by_sql` patch.

## v0.8.0 / 2024-10-22

- BREAKING CHANGE: Rename Active Record find_by_sql spans to query
- FIXED: Emit Active Record query spans for Rails 7.0+

## v0.7.4 / 2024-08-19

- FIXED: Use ActiveSupport from top-level namespace (NoMethodError on_load)

## v0.7.3 / 2024-08-15

- FIXED: Use Active Support Lazy Load Hooks to avoid prematurely initializing ActiveRecord::Base and ActiveJob::Base

## v0.7.2 / 2024-04-30

- FIXED: Resolve active_record testing issue

## v0.7.1 / 2024-04-05

- FIXED: Instrumentation/active_record: add `:allow_retry` option to `find_by_sql` patch

## v0.7.0 / 2023-11-22

- BREAKING CHANGE: Drop Rails 6.0 EOL
- ADDED: Drop Rails 6.0 EOL

## v0.6.3 / 2023-10-16

- FIXED: Add Rails 7.1 compatibility

## v0.6.2 / 2023-08-14

- FIXED: Ensure that transaction name property is used, rather than self

## v0.6.1 / 2023-06-05

- FIXED: Base config options

## v0.6.0 / 2023-04-17

- BREAKING CHANGE: Drop support for EoL Ruby 2.7
- ADDED: Drop support for EoL Ruby 2.7

## v0.5.0 / 2023-02-01

- BREAKING CHANGE: Drop Rails 5 Support
- ADDED: Drop Rails 5 Support

## v0.4.1 / 2023-01-14

- DOCS: Fix gem homepage
- DOCS: More gem documentation fixes

## v0.4.0 / 2022-06-09

- Upgrading Base dependency version
- FIXED: Broken test file requirements

## v0.3.0 / 2022-05-02

- ADDED: Make ActiveRecord 7 compatible
- FIXED: RubyGems Fallback

## v0.2.2 / 2021-12-01

- FIXED: Add max supported version for active record

## v0.2.1 / 2021-09-29

- (No significant changes)

## v0.2.0 / 2021-09-29

- ADDED: Trace update_all and delete_all calls in ActiveRecord
- FIXED: Remove Active Record instantiation patch

## v0.1.1 / 2021-08-12

- (No significant changes)

## v0.1.0 / 2021-07-08

- Initial release, adds instrumentation patches to querying and persistence methods.
