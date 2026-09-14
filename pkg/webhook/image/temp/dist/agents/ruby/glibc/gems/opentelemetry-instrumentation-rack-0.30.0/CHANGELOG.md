# Release History: opentelemetry-instrumentation-rack

### v0.30.0 / 2026-03-17

* BREAKING CHANGE: Default to stable HTTP semantic conventions (#2051)
* ADDED: Default to stable HTTP semantic conventions (#2051)

### v0.29.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2
* ADDED: Min Ruby Version 3.2

### v0.28.2 / 2025-10-07

* FIXED: Unify rack middleware_args

### v0.28.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.28.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.27.1 / 2025-09-16

* DOCS: Typo in Rack::Instrumentation usage example of middleware_args

### v0.27.0 / 2025-08-19

* ADDED: Add `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable compatibility [#1594](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1594)

### v0.26.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1
* ADDED: Set minimum supported version to Ruby 3.1

### v0.25.0 / 2024-10-23

* ADDED: Set span error only for 5xx response range

### v0.24.6 / 2024-07-23

* DOCS: Add cspell to CI

### v0.24.5 / 2024-06-18

* FIXED: Relax otel common gem constraints

### v0.24.4 / 2024-05-09

* FIXED: Untrace entire request

### v0.24.3 / 2024-05-08

* FIXED: Rack event baggage handling

### v0.24.2 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.24.1 / 2024-04-05

* DOCS: Fix typo where Rake is mentioned instead of Rack

### v0.24.0 / 2024-01-06

* BREAKING CHANGE: Use Rack Events By Default
* ADDED: Use Rack Events By Default
* FIXED: Backport Rack proxy event to middleware

### v0.23.5 / 2023-11-23

* CHANGED: Applied Rubocop Performance Recommendations [#727](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/727)

### v0.23.4 / 2023-08-03

* FIXED: Remove inline linter rules

### v0.23.3 / 2023-07-21

* ADDED: Update `opentelemetry-common` from [0.19.3 to 0.20.0](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/537)

### v0.23.2 / 2023-06-08

* FIXED: Ensure Rack Events Handler Exists

### v0.23.1 / 2023-06-05

* FIXED: Base config options

### v0.23.0 / 2023-04-17

* BREAKING CHANGE: Remove retain_middleware_names Rack Option
* BREAKING CHANGE: Drop support for EoL Ruby 2.7
* ADDED: Remove retain_middleware_names Rack Option
* ADDED: Drop support for EoL Ruby 2.7
* ADDED: Use Rack::Events for instrumentation

### v0.22.1 / 2023-01-14

* DOCS: Fix gem homepage
* DOCS: More gem documentation fixes

### v0.22.0 / 2022-11-16

* ADDED: Add experimental traceresponse propagator to Rack instrumentation

### v0.21.1 / 2022-10-04

* FIXED: Bring http.request.header and http.response.header in line with semconv

### v0.21.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements

### v0.20.2 / 2022-05-02

* FIXED: Update server instrumentation to not reflect 400 status as error

### v0.20.1 / 2021-12-01

* FIXED: [Instrumentation Rack] Log content type http header
* FIXED: Use monotonic clock where possible
* FIXED: Rack to stop using api env getter

### v0.20.0 / 2021-10-06

* FIXED: Prevent high cardinality rack span name as a default [#973](https://github.com/open-telemetry/opentelemetry-ruby/pull/973)

The default was to set the span name as the path of the request, we have
corrected this as it was not adhering to the spec requirement using low
cardinality span names.  You can restore the previous behavior of high
cardinality span names by passing in a url quantization function that
forwards the uri path.  More details on this is available in the readme.

### v0.19.3 / 2021-09-29

* (No significant changes)

### v0.19.2 / 2021-08-18

* FIXED: Rack middleware assuming script_name presence

### v0.19.1 / 2021-08-12

* DOCS: Update docs to rely more on environment variable configuration

### v0.19.0 / 2021-06-23

* BREAKING CHANGE: Total order constraint on span.status=
* ADDED: Add Tracer.non_recording_span to API
* FIXED: Total order constraint on span.status=

### v0.18.0 / 2021-05-21

* ADDED: Updated API dependency for 1.0.0.rc1
* FIXED: Removed http.status_text attribute #750

### v0.17.0 / 2021-04-22

* (No significant changes)

### v0.16.0 / 2021-03-17

* BREAKING CHANGE: Pass env to url quantization rack config to allow more flexibility
* ADDED: Pass env to url quantization rack config to allow more flexibility
* ADDED: Add rack instrumentation config option to accept callable to filter requests to trace
* FIXED: Example scripts now reference local common lib
* DOCS: Replace Gitter with GitHub Discussions

### v0.15.0 / 2021-02-18

* ADDED: Add instrumentation config validation

### v0.14.0 / 2021-02-03

* BREAKING CHANGE: Replace getter and setter callables and remove rack specific propagators
* ADDED: Replace getter and setter callables and remove rack specific propagators
* ADDED: Add untraced endpoints config to rack middleware

### v0.13.0 / 2021-01-29

* FIXED: Only include user agent when present

### v0.12.0 / 2020-12-24

* (No significant changes)

### v0.11.0 / 2020-12-11

* FIXED: Copyright comments to not reference year

### v0.10.1 / 2020-12-09

* FIXED: Rack current_span

### v0.10.0 / 2020-12-03

* (No significant changes)

### v0.9.0 / 2020-11-27

* BREAKING CHANGE: Add timeout for force_flush and shutdown
* ADDED: Instrument rails
* ADDED: Add timeout for force_flush and shutdown

### v0.8.0 / 2020-10-27

* BREAKING CHANGE: Move context/span methods to Trace module
* BREAKING CHANGE: Remove 'canonical' from status codes
* FIXED: Move context/span methods to Trace module
* FIXED: Remove 'canonical' from status codes

### v0.7.0 / 2020-10-07

* FIXED: Remove superfluous file from Rack gem
* DOCS: Added README for Rack Instrumentation
* DOCS: Standardize top-level docs structure and readme

### v0.6.0 / 2020-09-10

* (No significant changes)
