# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/runtime_guard'

class RuntimeGuardTest < Minitest::Test
  def test_sdk_disabled
    assert Beyla::OpenTelemetry::RuntimeGuard.disabled?('OTEL_SDK_DISABLED' => 'TRUE')
  end

  def test_sdk_enabled_by_default
    refute Beyla::OpenTelemetry::RuntimeGuard.disabled?({})
  end

  def test_rejects_other_engines
    assert_match(/JRuby/, Beyla::OpenTelemetry::RuntimeGuard.rejection('JRuby', '3.3.0'))
  end

  def test_rejects_old_ruby
    assert_match(/3\.2\.9/, Beyla::OpenTelemetry::RuntimeGuard.rejection('ruby', '3.2.9'))
  end

  def test_accepts_minimum_ruby
    assert_nil Beyla::OpenTelemetry::RuntimeGuard.rejection('ruby', '3.3.0')
  end

  def test_accepts_newer_ruby
    assert_nil Beyla::OpenTelemetry::RuntimeGuard.rejection('ruby', '4.0.0')
  end
end
