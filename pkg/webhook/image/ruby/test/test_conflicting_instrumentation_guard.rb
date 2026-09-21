# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/conflicting_instrumentation_guard'

class ConflictingInstrumentationGuardTest < Minitest::Test
  Snapshot = Struct.new(:gems) do
    def detected?(name)
      gems.include?(name)
    end
  end

  def test_rejects_instrumentation_dependencies
    {
      'datadog' => 'Datadog',
      'ddtrace' => 'Datadog',
      'onesdk_ruby' => 'Dynatrace',
      'newrelic_rpm' => 'New Relic',
      'newrelic-infinite_tracing' => 'New Relic'
    }.each do |gem, vendor|
      reason = rejection(Snapshot.new([gem]))

      assert_includes reason, vendor
      assert_includes reason, gem
    end
  end

  def test_rejects_loaded_instrumentation
    {
      '/gems/datadog-2.0/lib/datadog/auto_instrument.rb' => 'Datadog',
      '/gems/ddtrace-1.0/lib/ddtrace.rb' => 'Datadog',
      '/gems/onesdk_ruby-1.0/lib/onesdk_ruby.rb' => 'Dynatrace',
      '/gems/newrelic_rpm-10.0/lib/new_relic/agent.rb' => 'New Relic'
    }.each do |feature, vendor|
      assert_includes rejection(nil, '', [feature]), vendor
    end
  end

  def test_rejects_rubyopt_preloads
    assert_includes rejection(nil, '-rdatadog/auto_instrument'), 'Datadog'
    assert_includes rejection(nil, '-r onesdk_ruby'), 'Dynatrace'
    assert_includes rejection(nil, '-rnewrelic_rpm'), 'New Relic'
    assert_includes rejection(nil, '-rnewrelic/infinite_tracing'), 'New Relic'
  end

  def test_accepts_unrelated_dependencies_and_features
    snapshot = Snapshot.new(['datadog_api_client'])

    assert_nil rejection(snapshot, '-rapp/datadog_report', ['/app/new_relic_report.rb'])
  end

  private

  def rejection(snapshot, rubyopt = '', loaded_features = [])
    Beyla::OpenTelemetry::ConflictingInstrumentationGuard.rejection(snapshot, rubyopt, loaded_features)
  end
end
