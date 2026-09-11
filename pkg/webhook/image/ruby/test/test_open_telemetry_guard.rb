# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/open_telemetry_guard'

class OpenTelemetryGuardTest < Minitest::Test
  Snapshot = Struct.new(:direct_dependencies)
  ENTRYPOINT = '/otel/opentelemetry-auto-instrumentation.rb'

  def test_rejects_loaded_sdk
    reason = rejection(nil, '', ['/gems/opentelemetry/sdk.rb'])

    assert_match(/already loaded/, reason)
  end

  def test_rejects_loaded_api
    reason = rejection(nil, '', ['/gems/opentelemetry-api/lib/opentelemetry.rb'])

    assert_match(/already loaded/, reason)
  end

  def test_accepts_loaded_entrypoint
    assert_nil rejection(nil, '', [ENTRYPOINT])
  end

  def test_rejects_direct_otel_dependency
    reason = rejection(Snapshot.new(['opentelemetry-api']), '')

    assert_match(/bundle declares/, reason)
  end

  def test_rejects_other_rubyopt_preload
    reason = rejection(nil, "-r #{ENTRYPOINT} -ropentelemetry/sdk")

    assert_match(/RUBYOPT/, reason)
  end

  def test_accepts_own_rubyopt_preload
    assert_nil rejection(nil, "-r #{ENTRYPOINT}")
  end

  private

  def rejection(snapshot, rubyopt, loaded_features = [])
    Beyla::OpenTelemetry::OpenTelemetryGuard.rejection(snapshot, rubyopt, ENTRYPOINT, loaded_features)
  end
end
