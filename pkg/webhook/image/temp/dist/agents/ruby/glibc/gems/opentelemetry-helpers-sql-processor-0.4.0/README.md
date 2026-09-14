# OpenTelemetry Instrumentation Helpers: SQL Processor

This Ruby gem contains logic to process SQL, including obfuscation. It's intended for use by gem authors instrumenting SQL adapter libraries, such as mysql2, pg, and trilogy.

Obfuscation logic is largely drawn from the [New Relic Ruby agent's SQL Obfuscation Helpers module][new-relic-obfuscation-helpers].

## Usage

Add the gem to your instrumentation's gemspec file:

```ruby
# opentelemetry-instrumentation-your-gem.gemspec
  spec.add_dependency 'opentelemetry-helpers-sql-processor'
```

Add the gem to your instrumentation's Gemfile:

```ruby
# Gemfile

group :test do
  gem 'opentelemetry-helpers-sql-processor', path: '../../helpers/sql-processor'
end
```

## Obfuscation

Make sure the `Instrumentation` class for your gem contains configuration options for:

- `:obfuscation_limit`: the length at which the SQL string will not be obfuscated
  Example: `option :obfuscation_limit, default: 2000, validate: :integer`

If you want to add support for a new adapter, update the following constants to include keys for your adapter:

- `DIALECT_COMPONENTS`
- `CLEANUP_REGEX`

You must also add a new constant that calls the `generate_regex` method with your adapter's DIALECT_COMPONENTS that is named like `<ADAPTER>_COMPONENTS_REGEX`, such as: `MYSQL_COMPONENTS_REGEX`.

Check [New Relic's SQL Obfuscation Helpers module][new-relic-obfuscation-helpers] to see if regular expressions for your adapter already exist.

### Examples

To obfuscate sql in your library:

```ruby
OpenTelemetry::Helpers::SqlProcessor.obfuscate_sql(sql, obfuscation_limit: config[:obfuscation_limit], adapter: :postgres)
```

## How can I get involved?

The `opentelemetry-helpers-sql-processor` gem source is [on github][repo-github], along with related gems including `opentelemetry-instrumentation-pg` and `opentelemetry-instrumentation-trilogy`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-helpers-sql-processor` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[new-relic-obfuscation-helpers]: https://github.com/newrelic/newrelic-ruby-agent/blob/96e7aca22c1c873c0f5fe704a2b3bb19652db68e/lib/new_relic/agent/database/obfuscation_helpers.rb
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
