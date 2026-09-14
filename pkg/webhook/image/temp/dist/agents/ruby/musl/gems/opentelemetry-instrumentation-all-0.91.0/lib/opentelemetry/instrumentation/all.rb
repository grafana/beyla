# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require 'opentelemetry-instrumentation-anthropic'
require 'opentelemetry-instrumentation-active_support'
require 'opentelemetry-instrumentation-action_pack'
require 'opentelemetry-instrumentation-active_job'
require 'opentelemetry-instrumentation-active_record'
require 'opentelemetry-instrumentation-action_view'
require 'opentelemetry-instrumentation-action_mailer'
require 'opentelemetry-instrumentation-active_storage'
require 'opentelemetry-instrumentation-aws_sdk'
require 'opentelemetry-instrumentation-aws_lambda'
require 'opentelemetry-instrumentation-bunny'
require 'opentelemetry-instrumentation-lmdb'
require 'opentelemetry-instrumentation-http'
require 'opentelemetry-instrumentation-httpx'
require 'opentelemetry-instrumentation-koala'
require 'opentelemetry-instrumentation-active_model_serializers'
require 'opentelemetry-instrumentation-concurrent_ruby'
require 'opentelemetry-instrumentation-dalli'
require 'opentelemetry-instrumentation-delayed_job'
require 'opentelemetry-instrumentation-ethon'
require 'opentelemetry-instrumentation-excon'
require 'opentelemetry-instrumentation-faraday'
require 'opentelemetry-instrumentation-grape'
require 'opentelemetry-instrumentation-graphql'
require 'opentelemetry-instrumentation-grpc'
require 'opentelemetry-instrumentation-gruf'
require 'opentelemetry-instrumentation-http_client'
require 'opentelemetry-instrumentation-mongo'
require 'opentelemetry-instrumentation-mysql2'
require 'opentelemetry-instrumentation-net_http'
require 'opentelemetry-instrumentation-pg'
require 'opentelemetry-instrumentation-que'
require 'opentelemetry-instrumentation-racecar'
require 'opentelemetry-instrumentation-rack'
require 'opentelemetry-instrumentation-rails'
require 'opentelemetry-instrumentation-rake'
require 'opentelemetry-instrumentation-rdkafka'
require 'opentelemetry-instrumentation-redis'
require 'opentelemetry-instrumentation-restclient'
require 'opentelemetry-instrumentation-resque'
require 'opentelemetry-instrumentation-ruby_kafka'
require 'opentelemetry-instrumentation-sidekiq'
require 'opentelemetry-instrumentation-sinatra'
require 'opentelemetry-instrumentation-trilogy'

# OpenTelemetry is an open source observability framework, providing a
# general-purpose API, SDK, and related tools required for the instrumentation
# of cloud-native software, frameworks, and libraries.
#
# The OpenTelemetry module provides global accessors for telemetry objects.
# See the documentation for the `opentelemetry-api` gem for details.
module OpenTelemetry
  module Instrumentation
    # Namespace for the Opentelemetry all-in-one gem
    module All
    end
  end
end

require_relative 'all/version'
