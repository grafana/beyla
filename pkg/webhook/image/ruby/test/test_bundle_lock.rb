# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/bundle_lock'

class BundleLockTest < Minitest::Test
  LOCKFILE = <<~LOCK
    GEM
      remote: https://rubygems.org/
      specs:
        google-protobuf (4.35.1)
        rails (7.1.2)

    PLATFORMS
      ruby

    DEPENDENCIES
      rails

    BUNDLED WITH
       2.6.2
  LOCK

  def setup
    parser = Bundler::LockfileParser.new(LOCKFILE)
    @snapshot = Beyla::OpenTelemetry::BundleSnapshot.new(parser)
  end

  def test_records_direct_dependencies
    assert_equal ['rails'], @snapshot.direct_dependencies
  end

  def test_records_resolved_versions
    assert_equal ['7.1.2'], @snapshot.versions('rails')
    assert_equal ['4.35.1'], @snapshot.versions('google-protobuf')
  end

  def test_reports_missing_gems
    refute @snapshot.detected?('opentelemetry-sdk')
    assert_empty @snapshot.versions('opentelemetry-sdk')
  end

  def test_missing_lockfile_fails_open
    Bundler.stub(:default_lockfile, Pathname('/missing/Gemfile.lock')) do
      assert_nil Beyla::OpenTelemetry::BundleLock.load
    end
  end

  def test_unreadable_lockfile_fails_open
    Bundler.stub(:default_lockfile, Pathname(__FILE__)) do
      Bundler.stub(:read_file, ->(_) { raise 'unreadable' }) do
        assert_nil Beyla::OpenTelemetry::BundleLock.load
      end
    end
  end
end
