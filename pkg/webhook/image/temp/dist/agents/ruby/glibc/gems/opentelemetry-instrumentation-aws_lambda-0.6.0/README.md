# OpenTelemetry AWS-Lambda Instrumentation

The OpenTelemetry `aws-lambda` gem is a community-maintained instrumentation for [AWS Lambda functions](https://docs.aws.amazon.com/lambda/latest/dg/ruby-handler.html).

## How do I get started?

Installation of the `opentelemetry-instrumentation-aws_lambda` gem is handled by the [OpenTelemetry Lambda Layer for Ruby](https://github.com/open-telemetry/opentelemetry-lambda/tree/main/ruby).

We do not advise installing the `opentelemetry-instrumentation-aws_lambda` gem directly into your Ruby lambda. Instead, clone the [OpenTelemetry Lambda Layer for Ruby](https://github.com/open-telemetry/opentelemetry-lambda/tree/main/ruby) and build the layer locally. Then, save it in your AWS account.

## Usage

From the Lambda Layer side, create the wrapper. More information can be found at <https://github.com/open-telemetry/opentelemetry-lambda/tree/main/ruby>

Below is an example of `ruby/src/layer/wrapper.rb`, where you can configure the layer to suit your needs before building it:

```ruby
require 'opentelemetry/sdk'
require 'opentelemetry/instrumentation/aws_lambda'
OpenTelemetry::SDK.configure do |c|
  c.service_name = '<YOUR_SERVICE_NAME>'
  c.use 'OpenTelemetry::Instrumentation::AwsLambda'
end

def otel_wrapper(event:, context:)
  otel_wrapper = OpenTelemetry::Instrumentation::AwsLambda::Handler.new()
  otel_wrapper.call_wrapped(event: event, context: context)
end
```

### Alternative Usage

If using a Lambda Layer is not an option for your given setup, you can programmatically instrument a handler by using the `OpenTelemetry::Instrumentation::AwsLambda::Wrap` module.

```ruby
require 'opentelemetry/sdk'
require 'opentelemetry/instrumentation/aws_lambda'

OpenTelemetry::SDK.configure do |c|
  c.service_name = '<YOUR_SERVICE_NAME>'
  c.use 'OpenTelemetry::Instrumentation::AwsLambda'
end

# Lambda Handler
module Example
  class Handler
    extend OpenTelemetry::Instrumentation::AwsLambda::Wrap

    def self.process(event:, context:)
      puts event.inspect
    end
    instrument_handler :process
  end
end
```

## Example

To run the example:

1. `cd` to the examples directory and install gems
	* `cd example`
	* `bundle install`
2. Run the sample client script
	* `ruby trace_demonstration.rb`
	* or `bundle exec ruby trace_demonstration.rb`

This will run SNS publish command, printing OpenTelemetry traces to the console as it goes.

## How can I get involved?

The `opentelemetry-instrumentation-aws_lambda` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

Apache 2.0 license. See [LICENSE][license-github] for more information.

[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
