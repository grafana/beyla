# OpenTelemetry AWS-SDK Instrumentation

The OpenTelemetry `aws-sdk` gem is a community maintained instrumentation for [aws-sdk-ruby][aws-sdk-home].

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-aws_sdk
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-aws_sdk` in your `Gemfile`.

## Usage

To install the instrumentation, call `use` with the name of the instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::AwsSdk', {
    inject_messaging_context: true,
	enable_internal_instrumentation: true
  }
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```
### Configuration options
This instrumentation offers the following configuration options: 
* `:inject_messaging_context` (default: `false`): When set to `true`, adds context key/value 
 to Message Attributes for SQS/SNS messages.
* `:enable_internal_instrumentation` (default: `false`): When set to `true`, any spans with 
 span kind of `internal` are traced.
* `:suppress_internal_instrumentation`: **Deprecated**. This configuration has been
 deprecated in favor of `:enable_internal_instrumentation`

## Integration with SDK V3's Telemetry support
AWS SDK for Ruby V3 added support for Observability which includes a new configuration, 
`telemetry_provider` and an OpenTelemetry-based telemetry provider. Only applies to
AWS service gems released after 2024-09-03. 

Using later versions of these gems will give more details on the internal spans. 
See below for example usage:
```ruby
# configures the OpenTelemetry SDK with instrumentation defaults
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::AwsSdk'
end

# create open-telemetry provider and pass to client config
otel_provider = Aws::Telemetry::OTelProvider.new
client = Aws::S3::Client.new(telemetry_provider: otel_provider)
```

## Example

To run the example:

1. `cd` to the examples directory and install gems
	* `cd example`
	* `bundle install`
2. Run the sample client script
	* `ruby trace_demonstration.rb`

This will run SNS publish command, printing OpenTelemetry traces to the console as it goes.

## How can I get involved?

The `opentelemetry-instrumentation-aws_sdk` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

Apache 2.0 license. See [LICENSE][license-github] for more information.

[aws-sdk-home]: https://github.com/aws/aws-sdk-ruby
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
