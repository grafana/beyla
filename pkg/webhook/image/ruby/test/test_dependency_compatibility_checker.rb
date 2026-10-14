# frozen_string_literal: true

require_relative 'test_helper'
require 'beyla/dependency_compatibility_checker'

class DependencyCompatibilityCheckerTest < Minitest::Test
  Snapshot = Struct.new(:values) do
    def detected?(name)
      values.key?(name)
    end

    def versions(name)
      values.fetch(name, [])
    end
  end

  Spec = Struct.new(:name, :version, :full_gem_path, :full_require_paths)

  def test_uses_compatible_application_protobuf
    snapshot = Snapshot.new({ 'google-protobuf' => ['4.35.1'] })
    spec = gem_spec('google-protobuf', '4.35.1')

    result = with_specs([spec]) { guard(snapshot).check_dependencies }

    assert_nil result.rejection
    assert_includes result.exclusions, 'google-protobuf'
    assert_equal ['/app/gems/google-protobuf/lib'], result.load_paths
  end

  def test_rejects_incompatible_application_protobuf
    snapshot = Snapshot.new({ 'google-protobuf' => ['3.25.0'] })

    result = with_specs([gem_spec('google-protobuf', '3.25.0')]) { guard(snapshot).check_dependencies }

    assert_match(/incompatible/, result.rejection)
  end

  def test_rejects_newer_application_protobuf
    snapshot = Snapshot.new({ 'google-protobuf' => ['5.0.0'] })

    result = with_specs([gem_spec('google-protobuf', '5.0.0')]) { guard(snapshot).check_dependencies }

    assert_match(/incompatible/, result.rejection)
  end

  def test_uses_compatible_common_protos
    snapshot = Snapshot.new({ 'googleapis-common-protos-types' => ['1.23.0'] })
    spec = gem_spec('googleapis-common-protos-types', '1.23.0')

    result = with_specs([spec]) { guard(snapshot).check_dependencies }

    assert_nil result.rejection
    assert_includes result.exclusions, 'googleapis-common-protos-types'
    assert_equal ['/app/gems/googleapis-common-protos-types/lib'], result.load_paths
  end

  def test_rejects_unresolved_helper
    snapshot = Snapshot.new({ 'google-protobuf' => ['4.26.0', '4.35.1'] })

    result = with_specs([]) { guard(snapshot).check_dependencies }

    assert_match(/cannot be determined/, result.rejection)
  end

  def test_rejects_missing_application_copy
    snapshot = Snapshot.new({ 'google-protobuf' => ['4.35.1'] })

    result = with_specs([]) { guard(snapshot).check_dependencies }

    assert_match(/not available/, result.rejection)
  end

  def test_preserves_user_exclusions
    result = with_specs([]) { guard(nil, 'custom-helper').check_dependencies }

    assert_nil result.rejection
    assert_equal ['custom-helper'], result.exclusions
  end

  def test_validates_user_excluded_helpers
    result = with_specs([]) { guard(nil, 'google-protobuf').check_dependencies }

    assert_match(/cannot be determined/, result.rejection)
  end

  def test_rejects_helper_loaded_from_injection_bundle
    snapshot = Snapshot.new({ 'google-protobuf' => ['4.35.1'] })
    loaded = { 'google-protobuf' => gem_spec('google-protobuf', '4.35.1', '/otel') }

    result = with_specs([]) { guard(snapshot, nil, loaded).check_dependencies }

    assert_match(/injection bundle/, result.rejection)
  end

  private

  def guard(snapshot, exclusions = nil, loaded = {})
    env = exclusions ? { 'DISALLOWED_LIB_PATH' => exclusions } : {}
    Beyla::OpenTelemetry::DependencyCompatibilityChecker.new(snapshot, '/otel', env, loaded)
  end

  def gem_spec(name, version, root = '/app/gems')
    Spec.new(name, Gem::Version.new(version), "#{root}/#{name}", ["#{root}/#{name}/lib"])
  end

  def with_specs(specs, &block)
    Gem::Specification.stub(:find_all_by_name, specs, &block)
  end
end
