# OpenTelemetry Instrumentation Base

The `opentelemetry-instrumentation-base` gem contains the instrumentation base class, and the instrumentation registry. These modules provide a common interface to support the installation of auto instrumentation libraries. The instrumentation base is responsible for adding itself to the instrumentation registry as well as providing convenience hooks for the installation process. The instrumentation registry contains all the instrumentation to be installed during the SDK configuration process.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-base
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-base` in your `Gemfile`.

### For SDK Authors

The following is a simplified demonstration of how the `OpenTelemetry::Instrumentation.registry` can be used by an SDK to install auto-instrumentation gems as part of its configuration. This should not be used as an example of how to implement an SDK as there are large omissions. For an example of a complete implementation see the `opentelemetry-sdk` gem.

```ruby
require 'bundler/inline'

gemfile(true) do
  source 'https://rubygems.org'
  gem 'opentelemetry-api'
  gem 'opentelemetry-instrumentation-base'
  gem 'opentelemetry-instrumentation-net_http'
end

require 'opentelemetry-api'
require 'opentelemetry-instrumentation-base'

# Setup a noop custom tracer for our SDK
class MyCustomTracer < OpenTelemetry::Trace::Tracer
  def initialize(name, version)
    @name = name
    @version = version
  end
end

# Setup a tracer provider for our SDK
class MyCustomTracerProvider < OpenTelemetry::Trace::TracerProvider
  def tracer(name = nil, version = nil)
    MyCustomTracer.new(name, version)
  end
end

class MyCustomSDK
  def self.configure(config = {})
    # It is important that we upgrade the API tracer provider to
    # our SDK tracer provider so that when the install hook is
    # called that our instrumentation libraries receive an
    # SDK tracer instead of the noop API tracer.
    OpenTelemetry.tracer_provider = MyCustomTracerProvider.new
    OpenTelemetry::Instrumentation.registry.install_all(config)
  end
end

# The config option being passed to through to the registry install_all method.
# This is not a valid configuration option for this instrumentation library
# so the Opentelemetry logger will receive a warning message.
config = { 'OpenTelemetry::Instrumentation::Net::HTTP' => { foo: 'bar' } }
MyCustomSDK.configure(config)

# The purpose of this line is to demonstrate that the instrumentation
# library has received the SDK tracer and is not using the default
# API noop tracer.
puts OpenTelemetry::Instrumentation::Net::HTTP::Instrumentation.instance.tracer.inspect

#### Output
# Fetching gem metadata from https://rubygems.org/..
# Resolving dependencies...
# Using bundler 1.17.3
# Using opentelemetry-api 0.16.0
# Using opentelemetry-common 0.16.0
# Using opentelemetry-instrumentation-base 0.16.0
# Using opentelemetry-instrumentation-net_http 0.16.0
# W, [2021-04-08T17:28:04.430002 #8425]  WARN -- : Instrumentation OpenTelemetry::Instrumentation::Net::HTTP ignored the following unknown configuration options [:foo]
# I, [2021-04-08T17:28:04.430697 #8425]  INFO -- : Instrumentation: OpenTelemetry::Instrumentation::Net::HTTP was successfully installed
# #<MyCustomTracer:0x00007faee43c6c58 @name="OpenTelemetry::Instrumentation::Net::HTTP", @version="0.16.0">
```

### For auto-instrumentation authors

The following is a simplified demonstration of how the `OpenTelemetry::Instrumentation::Base` class can be used to hook into the instrumentation registry, and the basic functionality provided.

```ruby
# A simple class to instrument
class SimpleClass
  def greeting
    puts "hello"
  end
end

# Our instrumentation patch
class SimplePatch
  def greeting
    tracer.in_span('SimpleClass#greeting') { super }
  end

  private

  # We can gain access to the instrumentation tracer using
  # the instance method available on the class inheriting
  # from the instrumentation base.
  def tracer
    CustomAutoInstrumentation.instance.tracer
  end
end

# The OpenTelemetry::Instrumentation::Base class will implicitly add
# any class that inherits from it to the registry.
# Note that the name of the instrumentation in the registry will match
# the class name and its namespace.  In this example the registry
# will contain 'CustomAutoInstrumentation', if it was within
# a module named `Legacy`, it would take the form `Legacy::CustomAutoInstrumentation`.
class CustomAutoInstrumentation < OpenTelemetry::Instrumentation::Base
  # The install hook is provided to apply patches through prepending
  # or using library hooks if available.
  install do |_config|
    patch
  end

  # The presence check provides a hook so that we can
  # test for the presence of the class we intend to patch.
  # If the presence check returns false, we will not
  # proceed with the installation hook.
  present do
    defined?(SimpleClass)
  end

  private

  def patch
    SimpleClass.prepend(SimplePatch)
  end
end
```

## How can I get involved?

The `opentelemetry-instrumentation-base` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-base` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
