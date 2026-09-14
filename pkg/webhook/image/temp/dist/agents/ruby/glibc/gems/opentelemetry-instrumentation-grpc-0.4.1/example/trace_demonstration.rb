require 'bundler/inline'

gemfile do
  source 'https://rubygems.org'
  gem 'grpc'
  gem 'opentelemetry-api'
  gem 'opentelemetry-common'
  gem 'opentelemetry-instrumentation-grpc', path: '../'
  gem 'opentelemetry-sdk'
end

require_relative 'proto/example_api_services_pb'
require_relative 'example_impl'

ENV['OTEL_TRACES_EXPORTER'] = 'console'
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Grpc'
end


# start the server
@service = ExampleImpl.new
server = GRPC::RpcServer.new(pool_size: 1, poll_period: 1)
server_port = server.add_http2_port('localhost:0', :this_port_is_insecure)
server.handle(ExampleImpl)
server_thread = Thread.new { server.run }
server.wait_till_running


# make a request
stub = Proto::Example::ExampleAPI::Stub.new("localhost:#{server_port}", :this_channel_is_insecure)
stub.example(Proto::Example::ExampleRequest.new(id: 1, name: 'test!'))

server.stop
server_thread.join
