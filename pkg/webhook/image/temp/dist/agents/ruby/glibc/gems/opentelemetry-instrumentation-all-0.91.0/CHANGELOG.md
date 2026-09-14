# Release History: opentelemetry-instrumentation-all

### v0.91.0 / 2026-03-17

* ADDED: Upgrade opentelemetry-instrumentation-anthropic to 0.4.0
* ADDED: Upgrade opentelemetry-instrumentation-dalli to 0.29.2
* ADDED: Upgrade opentelemetry-instrumentation-ethon to 0.28.0
* ADDED: Upgrade opentelemetry-instrumentation-excon to 0.28.0
* ADDED: Upgrade opentelemetry-instrumentation-faraday to 0.32.0
* ADDED: Upgrade opentelemetry-instrumentation-grape to 0.6.0
* ADDED: Upgrade opentelemetry-instrumentation-graphql to 0.31.2
* ADDED: Upgrade opentelemetry-instrumentation-http to 0.29.0
* ADDED: Upgrade opentelemetry-instrumentation-http_client to 0.28.0
* ADDED: Upgrade opentelemetry-instrumentation-httpx to 0.7.0
* ADDED: Upgrade opentelemetry-instrumentation-net_http to 0.28.0
* ADDED: Upgrade opentelemetry-instrumentation-racecar to 0.6.1
* ADDED: Upgrade opentelemetry-instrumentation-rack to 0.30.0
* ADDED: Upgrade opentelemetry-instrumentation-rails to 0.40.0
* ADDED: Upgrade opentelemetry-instrumentation-restclient to 0.27.0
* ADDED: Upgrade opentelemetry-instrumentation-sinatra to 0.29.0
* ADDED: Upgrade opentelemetry-instrumentation-trilogy to 0.67.0

### v0.90.1 / 2026-01-13

* ADDED: Fixed release version

### v0.90.0 / 2025-01-13

* ADDED: Add SQL Comment Propagator
* ADDED: HTTP Client Semconv v1.17 Span Naming

### v0.89.1 / 2025-12-03

* ADDED: Upgrade trilogy instrumentation to 0.65.1
* ADDED: Upgrade mysql2 instrumentation to 0.32.1
* ADDED: Upgrade pg instrumentation to 0.34.1

### v0.89.0 / 2025-12-02

* ADDED: Upgrade trilogy instrumentation to 0.65.0
* ADDED: Upgrade mysql2 instrumentation to 0.32.0
* ADDED: Upgrade pg instrumentation to 0.34.0
* ADDED: Upgrade que instrumentation to 0.12.0
* ADDED: Upgrade sidekiq instrumentation to 0.28.1

### v0.88.0 / 2025-11-26

* BREAKING CHANGE: Update Ethon span name when unknown method
* ADDED: Update Ethon span name when unknown method

### v0.87.0 / 2025-11-05

* ADDED: upgrade opentelemetry-instrumentation-pg to 0.33.0

### v0.86.1 / 2025-10-22

* ADDED: Updated minimum gem versions for dependent instrumentations

### v0.86.0 / 2025-10-21

* BREAKING CHANGE: Min Version Support For Ruby 3.2 and Rails 7.1
* ADDED: Min Version Support For Ruby 3.2 and Rails 7.1

### v0.85.0 / 2025-10-11

* BREAKING CHANGE: aws_sdk Suppress internal spans by default

### v0.84.0 / 2025-09-27

* ADDED: Minimum version of opentelemetry-api v1.7.0

### v0.83.0 / 2025-09-27

* ADDED: Update trilogy instrumentation to v0.62.0

### v0.82.0 / 2025-09-18

* BREAKING CHANGE: AWS Lambda: Check if span has the attributes method to avoid internal error
* FIXED: AWS Lambda: Check if span has the attributes method to avoid internal error

### v0.81.0 / 2025-09-16

* ADDED: Anthropic initial instrumentation
* ADDED: Add Net::HTTP `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1572](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1572)

### v0.80.0 / 2025-08-19

ADDED: Add `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable compatibility for Rack. This includes an integration with Action Pack (Rails) and Sinatra instrumentation libraries. [#1594](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1594)

### v0.79.0 / 2025-08-18

* ADDED: Add HTTPX instrumentation to all
* ADDED: Add Ethon `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1561](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1561)
* ADDED: Add Excon `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1569](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1569)
* ADDED: Add Faraday `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1592](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1592)
* ADDED: Add HTTPClient `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1588](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1588)
* ADDED: HTTPX `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1589](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1589)
* ADDED: Add REST Client `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable [#1568](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1568)

### v0.78.0 / 2025-06-17

* ADDED: Add `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable to HTTP.rb instrumentation [#1547](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/1547)

### v0.77.0 / 2025-06-03

* ADDED: Suppress internal spans with Faraday instrumentation
* FIXED: Handle force_flush for rake task with arguments

### v0.76.0 / 2025-05-06

* ADDED: Update minimum required version of rdkafka to 0.18.0

### v0.75.1 / 2025-04-16

* (No significant changes)

### v0.75.0 / 2025-04-15

* ADDED: Add `opentelemetry-instrumentation-grpc` to `-all`
* ADDED: Support meta protocol instrumentation for Dalli

### v0.74.0 / 2025-02-11

* ADDED: Rdkafka support to v0.19 including

### v0.73.1 / 2025-02-05

* FIXED: Add require active_storage instrumentation to `all`

### v0.73.0 / 2025-02-04

* CHANGED: opentelemetry-instrumentation-redis v0.26.1
* CHANGED: opentelemetry-instrumentation-rails v0.36.0
* CHANGED: opentelemetry-instrumentation-aws_lambda v0.3.0
* CHANGED: opentelemetry-instrumentation-action_pack v0.12.0

### v0.72.0 / 2025-01-16

* BREAKING CHANGE: Set minimum supported version to Ruby 3.1
* ADDED: Set minimum supported version to Ruby 3.1

### v0.71.1 / 2025-01-14

* No Significant Changes

### v0.71.0 / 2025-01-07

* ADDED: Faraday Minimum v1.0

### v0.70.0 / 2024-12-19

* ADDED: Upgrade ActiveSupport Instrumentation 0.7.0

### v0.69.1 / 2024-11-26

* (No significant changes)

### v0.69.0 / 2024-11-19

* ADDED: Use Semconv Naming For ActionPack

### v0.68.0 / 2024-10-23

* ADDED: Set span error only for 5xx response range

### v0.67.0 / 2024-10-22

* BREAKING CHANGE: Rename Active Record find_by_sql spans to query
* FIXED: Emit Active Record query spans for Rails 7.0+
* ADDED: Subscribe to process.action_mailer notifications

### v0.66.0 / 2024-10-08

* ADDED: Integration with V3 telemetry provider for the aws-sdk

### v0.65.0 / 2024-09-19

* ADDED: All AWS services emit traces

### v0.64.0 / 2024-09-12

- BREAKING CHANGE: Return message when sql is over the obfuscation limit. Fixes a bug where sql statements with prepended comments that hit the obfuscation limit would be sent raw.

### v0.63.0 / 2024-08-15

- ADDED: Collect pg db.collection_name attribute

### v0.62.1 / 2024-07-23

- DOCS: Add cspell to CI

### v0.62.0 / 2024-07-02

- DOCS: Fix CHANGELOGs to reflect a past breaking change
- CHANGED: Update Rails Instrumentation
- CHANGED: Update Grape Instrumentation
- CHANGED: Update Sinatra Instrumentation

### v0.61.0 / 2024-06-04

- ADDED: Add aws lambda to instrumentation-all
- FIXED: Add action_mailer to rails and all

### v0.60.0 / 2024-02-20

- ADDED: Add support gruf 2.19
- ADDED: Faraday add support for internal spans

### v0.59.0 / 2024-02-16

- BREAKING CHANGE: GraphQL Legacy Tracer perf improvements [#867](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/867).

### v0.58.0 / 2024-02-15

- CHANGED: upgrade mysql2 instrumentation

### v0.57.0 / 2024-02-08

- BREAKING CHANGE: Move shared sql behavior to helper gems

### v0.56.0 / 2024-01-09

- BREAKING CHANGE: Use ActiveSupport instead of patches #703

### v0.55.0 / 2024-01-06

- CHANGED: Upgrade Trilogy and Rack [#796](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/796)

### v0.54.0 / 2023-11-28

- ADDED: Updated excon to include connect spans

### v0.53.0 / 2023-11-28

- CHANGED: Performance optimization cache attribute hashes [#723](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/723)

### v0.52.0 / 2023-11-21

- BREAKING CHANGE: Drop Support for EoL Rails 6.0 [#680](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/680)
- BREAKING CHANGE: Use ActiveSupport Instrumentation instead of Money Patches [#677](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/677)

- CHANGED: Drop Support for EoL Rails 6.0 [#680](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/680)
- CHANGED: Use ActiveSupport Instrumentation instead of Money Patches [#677](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/677)

### v0.51.1 / 2023-10-27

- ADDED: Instrument connect and ping (Trilogy)

### v0.51.0 / 2023-10-16

- CHANGED: See [#695](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/695) for details

### v0.50.1 / 2023-09-07

- BREAKING CHANGE: Align messaging instrumentation operation names (Resque)

### v0.50.0 / 2023-09-07

- BREAKING CHANGE: Align messaging instrumentation operation names [#648](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/648)

### v0.40.0 / 2023-08-07

- ADDED: Add Gruf instrumentation

### v0.39.1 / 2023-06-05

- FIXED: Use latest bug fix version for all dependencies

### v0.39.0 / 2023-06-02

- BREAKING CHANGE: Separate logical MySQL host from connected host
- ADDED: Separate logical MySQL host from connected host

### v0.38.0 / 2023-05-31

- BREAKING CHANGE: Add database name for trilogy traces

- ADDED: Add database name for trilogy traces

### v0.37.0 / 2023-05-25

- ADDED: Add config[:obfuscation_limit] to pg and mysql2
- ADDED: Add Obfuscation Limit Option to Trilogy

### v0.36.0 / 2023-05-18

- ADDED: GraphQL instrumentation: support new tracing API (#453)
- ADDED: Add span_preprocessor hook (#456)
- ADDED: add db.operation attribute for dalli (#458)

### v0.35.0 / 2023-04-21

- ADDED: Re-add Grape instrumentation to opentelemetry-instrumentation-all

### v0.34.0 / 2023-04-17

- BREAKING CHANGE: Drop support for EoL Ruby 2.7

- ADDED: Drop support for EoL Ruby 2.7
- ADDED: Add Grape instrumentation

### v0.33.0 / 2023-03-15

- BREAKING CHANGE: Add support for GraphQL 2.0.19

- FIXED: Add support for GraphQL 2.0.19

### v0.32.0 / 2023-03-13

- BREAKING CHANGE: Lock graphql max version to 2.0.17
- FIXED: Lock graphql max version to 2.0.17
- ADDED: Add with_attributes context propagation to Trilogy instrumentation
- ADDED: Add option to configure span name for trilogy
- FIXED: Ensure encoding errors handled during SQL obfuscation for Trilogy

### v0.31.0 / 2023-02-09

- BREAKING CHANGE: Drop Rails 5 support [#324](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/324)

### v0.30.0 / 2023-01-31

- BREAKING CHANGE: Updates instrumentations [#303](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/303)

### v0.29.0 / 2023-01-14

- BREAKING CHANGE: includes minor version updates in [#271](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/271)

### v0.28.1 / 2023-01-14

- DOCS: Fix gem homepage
- DOCS: More gem documentation fixes

### v0.28.0 / 2022-11-09

- ADDED: Bump minimum gem versions for opentelemetry-instrumentation-all
- ADDED: Instrumentation for racecar
- CHANGED: Update rails instrumentation

### v0.27.0 / 2022-10-14

- CHANGED: Update Rails instrumentation

### v0.26.0 / 2022-10-12

- ADDED: Upgrade min instrumentation versions See For Details https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/134

### v0.25.0 / 2022-06-09

- Bump all dependencies to use base 0.21.0

### v0.24.1 / 2022-05-05

- (No significant changes)

### v0.24.0 / 2022-05-02

- ADDED: Adds instrumentation for rdkafka
- FIXED: Add rdkafka to all

### v0.23.0 / 2022-01-26

- ADDED: Add Trilogy Auto Instrumentation
- FIXED: `ActiveSupport` constant conflict in Active Model Serializers instrumentation
- FIXED: add missing require for aws_sdk instrumentation #1054

### v0.22.0 / 2021-12-01

- ADDED: Move activesupport notification subscriber out of action_view gem

### v0.21.3 / 2021-10-07

- (No significant changes)

### v0.21.2 / 2021-09-29

- (No significant changes)

### v0.21.1 / 2021-09-29

- (No significant changes)

### v0.21.0 / 2021-09-15

- ADDED: Add Que instrumentation

### v0.20.2 / 2021-09-09

- (No significant changes)

### v0.20.1 / 2021-08-18

- FIXED: Instrumentation all sidekiq

### v0.20.0 / 2021-08-12

- ADDED: Instrument active record
- ADDED: Add ActionView instrumentation via ActiveSupport::Notifications

### v0.19.0 / 2021-06-25

- ADDED: Add resque instrumentation
- ADDED: Add ActiveJob instrumentation
- ADDED: Configuration option to enable or disable redis root spans [#777](https://github.com/open-telemetry/opentelemetry-ruby/pull/777)
- FIXED: Broken instrumentation all release

### v0.18.0 / 2021-05-21

- ADDED: Add koala instrumentation

### v0.17.0 / 2021-04-22

- ADDED: Add instrumentation for postgresql (pg gem)

### v0.16.0 / 2021-03-17

- ADDED: Instrument http gem
- ADDED: Instrument lmdb gem
- FIXED: Example scripts now reference local common lib
- DOCS: Replace Gitter with GitHub Discussions

### v0.15.0 / 2021-02-18

- ADDED: Instrument http client gem

### v0.14.0 / 2021-02-03

- (No significant changes)

### v0.13.0 / 2021-01-29

- (No significant changes)

### v0.12.1 / 2021-01-13

- ADDED: Instrument RubyKafka

### v0.12.0 / 2020-12-24

- ADDED: Instrument graphql

### v0.11.0 / 2020-12-11

- FIXED: Copyright comments to not reference year

### v0.10.0 / 2020-12-03

- FIXED: Otel-instrumentation-all not installing all

### v0.9.0 / 2020-11-27

- ADDED: Add common helpers

### v0.8.0 / 2020-10-27

- (No significant changes)

### v0.7.0 / 2020-10-07

- DOCS: Standardize top-level docs structure and readme

### v0.6.0 / 2020-09-10

- Now depends on version 0.6.x of all the individual instrumentation gems.
