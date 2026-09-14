# frozen_string_literal: true

require 'bundler'
require 'rubygems'
require_relative 'dependency_requirements_generator'

def installed_specs(root)
  Dir.glob(File.join(root, 'specifications', '*.gemspec')).filter_map do |path|
    Gem::Specification.load(path)
  end
end

def find_spec(specs, name)
  specs.find { |spec| spec.name == name } || raise("#{name} is missing")
end

def verify_revision(lockfile, revision_file)
  revisions = File.read(lockfile).scan(/^  revision: ([0-9a-f]{40})$/).flatten
  expected = File.read(revision_file).strip
  raise 'upstream revision is not locked' unless revisions == [expected]
end

def verify_installed_versions(specs, parser)
  installed = specs.map { |spec| [spec.name, spec.version.to_s] }.uniq.sort
  locked = parser.specs.map { |spec| [spec.name, spec.version.to_s] }.uniq.sort
  raise 'installed gems differ from the lockfile' unless installed == locked
end

def dependencies(spec)
  DependencyRequirementsGenerator.dependencies(spec)
                                 .map { |dependency| [dependency.name, dependency.requirement.to_s] }.sort
end

def verify_upstream_dependencies(upstream, parser)
  locked = parser.specs.find { |spec| spec.name == upstream.name }
  raise 'upstream dependencies differ from the lockfile' unless locked && dependencies(upstream) == dependencies(locked)
end

def verify_ruby_policy(upstream, minimum)
  required = upstream.required_ruby_version
  raise 'Ruby compatibility policy is too old' unless required.satisfied_by?(Gem::Version.new(minimum))
  raise 'upstream Ruby compatibility has an upper bound' unless required.satisfied_by?(Gem::Version.new('999.0'))
end

def upstream_rails_version(root)
  pattern = File.join(
    root, 'gems', 'opentelemetry-instrumentation-rails-*', 'lib',
    'opentelemetry', 'instrumentation', 'rails', 'instrumentation.rb'
  )
  files = Dir.glob(pattern)
  source = files.one? && File.read(files.first)
  match = source && source.match(/MINIMUM_VERSION\s*=\s*Gem::Version\.new\(['"]([^'"]+)/)
  raise 'Rails compatibility policy cannot be verified' unless match

  Gem::Version.new(match[1])
end

def verify_rails_policy(root, minimum)
  configured = Gem::Version.new(minimum)
  raise 'Rails compatibility policy is weaker than upstream' if configured < upstream_rails_version(root)
end

def verify_dependency_requirements(specs, configured, api_requirements)
  actual = DependencyRequirementsGenerator.generate(specs)
  raise 'dependency compatibility policy differs from upstream' unless actual == configured

  actual_api = DependencyRequirementsGenerator.opentelemetry_api_requirements(specs)
  raise 'opentelemetry-api compatibility policy differs from upstream' unless actual_api == api_requirements
end

root, lockfile, revision_file = ARGV
require File.join(root, 'beyla', 'compatibility')
require File.join(root, 'beyla', 'dependency_requirements')

specs = installed_specs(root)
parser = Bundler::LockfileParser.new(File.read(lockfile))
upstream = find_spec(specs, 'opentelemetry-auto-instrumentation')

verify_revision(lockfile, revision_file)
verify_installed_versions(specs, parser)
verify_upstream_dependencies(upstream, parser)
verify_ruby_policy(upstream, Beyla::OpenTelemetry::Compatibility::MINIMUM_RUBY_VERSION)
verify_rails_policy(root, Beyla::OpenTelemetry::Compatibility::MINIMUM_RAILS_VERSION)
verify_dependency_requirements(
  specs,
  Beyla::OpenTelemetry::Compatibility::DEPENDENCY_REQUIREMENTS,
  Beyla::OpenTelemetry::Compatibility::OPENTELEMETRY_API_REQUIREMENTS
)
