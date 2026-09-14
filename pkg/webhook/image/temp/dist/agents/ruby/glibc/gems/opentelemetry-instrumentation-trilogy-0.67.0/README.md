# OpenTelemetry Trilogy Instrumentation

The OpenTelemetry Trilogy Ruby gem provides instrumentation for [Trilogy][trilogy-home] and
was `COPY+PASTE+MODIFIED` from the [`OpenTelemetry MySQL`][opentelemetry-mysql].

Some key differences in this instrumentation are:

- `Trilogy` does not expose [`MySql#query_options`](https://github.com/brianmario/mysql2/blob/ca08712c6c8ea672df658bb25b931fea22555f27/lib/mysql2/client.rb#L78), therefore there is limited support for database semantic conventions.
- SQL Obfuscation is enabled by default to mitigate restricted data leaks.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-trilogy
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-trilogy` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Trilogy', {
    # The obfuscation of SQL in the db.statement attribute is disabled by default.
    # To enable, set db_statement to :obfuscate.
    db_statement: :obfuscate,
  }
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

The `trilogy` instrumentation allows the user to supply additional attributes via the `with_attributes` method. This makes it possible to supply additional attributes on trilogy spans. Attributes supplied in `with_attributes` supersede those automatically generated within `trilogy`'s automatic instrumentation. If you supply a `db.statement` attribute in `with_attributes`, this library's `:db_statement` configuration will not be applied.

```ruby
require 'opentelemetry-instrumentation-trilogy'

client = Trilogy.new(:host => 'localhost', :username => 'root')
OpenTelemetry::Instrumentation::Trilogy.with_attributes('pizzatoppings' => 'mushrooms') do
  client.query('SELECT 1')
end
```

## Semantic Conventions

This instrumentation generally uses [Database semantic conventions](https://opentelemetry.io/docs/specs/semconv/database/database-spans/).

| Attribute Name | Type | Notes |
| - | - | - |
| `db.instance.id` | String | The name of the DB host executing the query e.g. `SELECT @@hostname` |
| `db.name` | String | The name of the database from connection_options |
| `db.statement` | String | SQL statement being executed |
| `db.user` | String | The username from connection_options |
| `db.system` | String | `mysql` |
| `net.peer.name` | String | The name of the remote host from connection_options |

## How can I get involved?

The `opentelemetry-instrumentation-trilogy` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-trilogy` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[trilogy-home]: https://github.com/github/trilogy
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
[opentelemetry-mysql]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/tree/main/instrumentation/mysql2
