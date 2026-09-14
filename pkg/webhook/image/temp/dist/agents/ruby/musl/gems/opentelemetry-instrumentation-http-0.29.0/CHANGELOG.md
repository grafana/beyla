# Release History: opentelemetry-instrumentation-http

### v0.29.0 / 2026-03-17

* BREAKING CHANGE: Default to stable HTTP semantic conventions (#2051)
* ADDED: Default to stable HTTP semantic conventions (#2051)

### v0.28.0 / 2026-01-13

* ADDED: HTTP Client Semconv v1.17 Span Naming

### v0.27.1 / 2025-11-25

* FIXED: Update support for unknown HTTP methods to match semantic conventions

### v0.27.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2
* ADDED: Min Ruby Version 3.2

### v0.26.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.26.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.25.1 / 2025-07-01

* FIXED: Update span name when semconv stability is enabled

### v0.25.0 / 2025-06-17

* ADDED: Add `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1547](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1547)

### v0.24.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1
* ADDED: Set minimum supported version to Ruby 3.1

### v0.23.5 / 2024-11-26

* CHANGED: Performance Freeze all range objects #1222

### v0.23.4 / 2024-07-23

* DOCS: Add cspell to CI

### v0.23.3 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.23.2 / 2023-11-23

* CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

### v0.23.1 / 2023-06-05

* FIXED: Base config options

### v0.23.0 / 2023-05-15

* ADDED: Add span_preprocessor hook

### v0.22.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7
* ADDED: Drop support for EoL Ruby 2.7

### v0.21.0 / 2023-01-14

* ADDED: Add request/response hooks to more http clients
* DOCS: Fix gem homepage
* DOCS: More gem documentation fixes

### v0.20.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements

### v0.19.6 / 2022-05-05

* (No significant changes)

### v0.19.5 / 2022-05-02

* FIXED: RubyGems Fallback

### v0.19.4 / 2022-02-02

* FIXED: Excessive hash creation on context attr merging

### v0.19.3 / 2021-12-01

* FIXED: Change net attribute names to match the semantic conventions spec for http

### v0.19.2 / 2021-09-29

* (No significant changes)

### v0.19.1 / 2021-08-12

* (No significant changes)

### v0.19.0 / 2021-06-23

* BREAKING CHANGE: Total order constraint on span.status=
* FIXED: Total order constraint on span.status=

### v0.18.0 / 2021-05-21

* ADDED: Updated API dependency for 1.0.0.rc1

### v0.17.0 / 2021-04-22

* FIXED: Refactor propagators to add #fields

### v0.16.2 / 2021-03-29

* FIXED: HTTP Instrumentation should check for gem presence

### v0.16.1 / 2021-03-25

* FIXED: HTTP instrumentation missing require

### v0.16.0 / 2021-03-17

* Initial release.
