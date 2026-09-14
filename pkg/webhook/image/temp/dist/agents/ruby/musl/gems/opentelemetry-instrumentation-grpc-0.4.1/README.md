# OpenTelemetry gRPC Instrumentation

[![Gem Version](https://badge.fury.io/rb/opentelemetry-instrumentation-grpc.svg)](https://badge.fury.io/rb/opentelemetry-instrumentation-grpc)
[![GitHub Actions CI Status](https://github.com/hibachrach/opentelemetry-instrumentation-grpc/actions/workflows/main.yml/badge.svg)](https://github.com/hibachrach/opentelemetry-instrumentation-grpc/actions?query=branch%3Amain)

OpenTelemetry instrumentation for users of the [gRPC](https://github.com/grpc/grpc/tree/master/src/ruby) gem.

> [!WARNING]
> Right now, the gem only instruments outbound requests to gRPC services

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-grpc
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-grpc` in your `Gemfile`.


## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
  OpenTelemetry::SDK.configure do |c|
    c.use 'OpenTelemetry::Instrumentation::Grpc', {
      peer_service: "Example",
      allowed_metadata_headers: [],
    }
  end
```

Alternatively, you can also call `use_all` to install all the available
instrumentation.

```ruby
  OpenTelemetry::SDK.configure do |c|
    c.use_all
  end
```

## Examples

Example usage can be seen in the [`./example/trace_demonstration.rb` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/grpc/example/trace_demonstration.rb)

## Development

Integration tests rely on a real gRPC server that is started by relevant tests. The proto definition is located in `test/support/proto/ping.proto`. Making changes to the proto definition requires re-creating gRPC-generated code. To do this, run the following command:

```sh
bundle exec grpc_tools_ruby_protoc --ruby_out=. --grpc_out=. test/support/proto/ping.proto
```

## How can I get involved?

The `opentelemetry-instrumentation-grpc` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-grpc` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[grpc-home]: https://github.com/grpc/grpc
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
