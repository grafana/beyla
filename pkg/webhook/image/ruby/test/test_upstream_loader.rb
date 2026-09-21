# frozen_string_literal: true

require_relative 'test_helper'
require 'fileutils'
require 'tmpdir'
require 'beyla/upstream_loader'

class UpstreamLoaderTest < Minitest::Test
  DependencyCheck = Struct.new(:load_paths, :exclusions)

  def test_loads_upstream_with_application_helpers
    application_path = '/app/google-protobuf/lib'
    previous = ENV['DISALLOWED_LIB_PATH']

    Dir.mktmpdir do |root|
      entrypoint = create_entrypoint(root)
      check = DependencyCheck.new([application_path], ['custom', 'google-protobuf'])
      ENV['DISALLOWED_LIB_PATH'] = 'custom'

      observed = nil
      Kernel.stub(:require, lambda { |path|
        observed = [path, ENV['DISALLOWED_LIB_PATH']]
        true
      }) do
        Beyla::OpenTelemetry::UpstreamLoader.new(root).call(check)
      end

      assert_equal [entrypoint, 'custom,google-protobuf'], observed
      assert_equal 'custom', ENV['DISALLOWED_LIB_PATH']
      assert_equal application_path, $LOAD_PATH.first
    ensure
      ENV['DISALLOWED_LIB_PATH'] = previous
      $LOAD_PATH.delete(application_path)
    end
  end

  def test_requires_one_upstream_entrypoint
    Dir.mktmpdir do |root|
      check = DependencyCheck.new([], [])

      assert_raises(LoadError) do
        Beyla::OpenTelemetry::UpstreamLoader.new(root).call(check)
      end
    end
  end

  private

  def create_entrypoint(root)
    path = File.join(root, 'gems', 'opentelemetry-auto-instrumentation-0.1.0', 'lib')
    FileUtils.mkdir_p(path)
    File.join(path, 'opentelemetry-auto-instrumentation.rb').tap { |file| File.write(file, '') }
  end
end
