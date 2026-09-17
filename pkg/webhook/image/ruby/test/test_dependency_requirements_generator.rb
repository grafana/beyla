# frozen_string_literal: true

require_relative 'test_helper'
require 'dependency_requirements_generator'
require 'beyla/compatibility'
require 'beyla/dependency_requirements'

class DependencyRequirementsGeneratorTest < Minitest::Test
  def test_generates_constrained_external_runtime_requirements
    specs = [
      gem_spec('opentelemetry-exporter', {
                 'opentelemetry-api' => ['~> 1.0'],
                 'google-protobuf' => ['>= 3.18', '< 5.0'],
                 'logger' => []
               }),
      gem_spec('google-protobuf', { 'bigdecimal' => [], 'rake' => ['~> 13.3'] }),
      gem_spec('googleapis', { 'google-protobuf' => ['~> 4.26'] })
    ]

    assert_equal({
                   'google-protobuf' => ['< 5.0', '>= 3.18', '~> 4.26']
                 }, DependencyRequirementsGenerator.generate(specs))
  end

  def test_generates_opentelemetry_api_requirements_separately
    specs = [
      gem_spec('opentelemetry-sdk', { 'opentelemetry-api' => ['~> 1.1'] }),
      gem_spec('opentelemetry-auto-instrumentation', { 'opentelemetry-api' => ['~> 1.9.0'] })
    ]

    assert_equal ['~> 1.1', '~> 1.9.0'],
                 DependencyRequirementsGenerator.opentelemetry_api_requirements(specs)
  end

  def test_committed_requirements_match_lockfile
    lockfile = File.join(RUBY_BUNDLE_ROOT, 'Gemfile.lock')

    assert_equal Beyla::OpenTelemetry::Compatibility::DEPENDENCY_REQUIREMENTS,
                 DependencyRequirementsGenerator.from_lockfile(lockfile)
    assert_equal Beyla::OpenTelemetry::Compatibility::OPENTELEMETRY_API_REQUIREMENTS,
                 DependencyRequirementsGenerator.opentelemetry_api_requirements_from_lockfile(lockfile)
  end

  private

  def gem_spec(name, dependencies)
    Gem::Specification.new do |spec|
      spec.name = name
      spec.version = '1.0.0'
      spec.summary = name
      spec.authors = ['test']
      spec.files = []
      dependencies.each { |dependency, requirements| spec.add_runtime_dependency(dependency, *requirements) }
    end
  end
end
