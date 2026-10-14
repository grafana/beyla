# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/protocol_guard'

class ProtocolGuardTest < Minitest::Test
  def test_accepts_default_protocol
    assert_nil rejection({})
  end

  def test_rejects_grpc_for_enabled_signals
    reason = rejection('OTEL_EXPORTER_OTLP_PROTOCOL' => 'grpc')

    assert_match(/traces, metrics, logs/, reason)
  end

  def test_ignores_disabled_signals
    env = {
      'OTEL_EXPORTER_OTLP_PROTOCOL' => 'grpc',
      'OTEL_TRACES_EXPORTER' => 'none',
      'OTEL_METRICS_EXPORTER' => 'none',
      'OTEL_LOGS_EXPORTER' => 'none'
    }

    assert_nil rejection(env)
  end

  def test_signal_protocol_overrides_shared_protocol
    env = {
      'OTEL_EXPORTER_OTLP_PROTOCOL' => 'grpc',
      'OTEL_EXPORTER_OTLP_TRACES_PROTOCOL' => 'http/protobuf',
      'OTEL_METRICS_EXPORTER' => 'none',
      'OTEL_LOGS_EXPORTER' => 'none'
    }

    assert_nil rejection(env)
  end

  private

  def rejection(env)
    Beyla::OpenTelemetry::ProtocolGuard.rejection(env)
  end
end
