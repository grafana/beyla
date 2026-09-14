# Release History: opentelemetry-instrumentation-aws_sdk

### v0.11.0 / 2025-10-22

* BREAKING CHANGE: Min Ruby Version 3.2

* ADDED: Min Ruby Version 3.2

### v0.10.0 / 2025-10-11

* BREAKING CHANGE: Suppress internal spans by default

* ADDED: Suppress internal spans by default

### v0.9.1 / 2025-09-30

* FIXED: Min OTel Ruby API 1.7

### v0.9.0 / 2025-09-30

* ADDED: Bump minimum API Version to 1.7

### v0.8.2 / 2025-08-13

* FIXED: net_http and aws_sdk ci fix

### v0.8.1 / 2025-05-13

* DOCS: Use AWS SDK v3 in example

### v0.8.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1

* ADDED: Set minimum supported version to Ruby 3.1

### v0.7.0 / 2024-10-08

* ADDED: Integration with V3 telemetry provider

### v0.6.0 / 2024-09-19

* ADDED: All AWS services emit traces

### v0.5.4 / 2024-07-23

* DOCS: Add cspell to CI

### v0.5.3 / 2024-07-02

* DOCS: Fix CHANGELOGs to reflect a past breaking change

### v0.5.2 / 2024-04-30

* FIXED: Bundler conflict warnings

### v0.5.1 / 2024-02-08

* FIXED: Return nil for non-existent key in AwsSdk::MessageAttributeGetter

### v0.5.0 / 2023-09-07

* BREAKING CHANGE: Align messaging instrumentation operation names [#648](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/648)

### v0.4.2 / 2023-08-03

* FIXED: Remove inline linter rules

### v0.4.1 / 2023-06-05

* FIXED: Base config options

### v0.4.0 / 2023-04-17

* BREAKING CHANGE: Drop support for EoL Ruby 2.7

* ADDED: Drop support for EoL Ruby 2.7

### v0.3.2 / 2023-01-14

* DOCS: Fix gem homepage
* DOCS: More gem documentation fixes

### v0.3.1 / 2022-07-19

* FIXED: Suppress invalid span attribute value type warning in aws-sdk instrumentation

### v0.3.0 / 2022-06-09

* Upgrading Base dependency version
* FIXED: Broken test file requirements

### v0.2.3 / 2022-05-02

* FIXED: RubyGems Fallback

### v0.2.2 / 2022-01-26

* (No significant changes)

### v0.2.1 / 2022-01-21

* ADDED: attach HTTP status code to AWS spans

### v0.2.0 / 2022-01-20

* ADDED: SQS / SNS messaging attributes and context propagation

### v0.1.0 / 2021-12-01

* Initial release.
