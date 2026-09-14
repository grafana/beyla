# OpenTelemetry::Resource::Detector::Azure

The `opentelemetry-resource-detector-azure` gem provides an Azure resource detector for OpenTelemetry.

## What is OpenTelemetry?

OpenTelemetry is an open source observability framework, providing a general-purpose API, SDK, and related tools required for the instrumentation of cloud-native software, frameworks, and libraries.

OpenTelemetry provides a single set of APIs, libraries, agents, and collector services to capture distributed traces and metrics from your application. You can analyze them using Prometheus, Jaeger, and other observability tools.

## How does this gem fit in?

The `opentelemetry-resource-detector-azure` gem provides a means of retrieving a resource for supported environments following the resource semantic conventions.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-sdk
gem install opentelemetry-resource-detector-azure
```

Or, if you use Bundler, include `opentelemetry-sdk` and `opentelemetry-resource-detector-azure` in your `Gemfile`.

```rb
require 'opentelemetry/sdk'
require 'opentelemetry/resource/detector'

OpenTelemetry::SDK.configure do |c|
  c.resource = OpenTelemetry::Resource::Detector::Azure.detect
end
```

This will populate the following resource attributes for compute running on Azure:

* `cloud.provider`
* `cloud.account.id`
* `cloud.platform`
* `cloud.region`
* `cloud.availability_zone`
* `host.id`
* `host.image.id`
* `host.name`
* `host.type`

## How can I get involved?

The `opentelemetry-resource-detector-azure` gem source is on GitHub, along with related gems.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-resource-detector-azure` gem is distributed under the Apache 2.0 license. See LICENSE for more information.

[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
