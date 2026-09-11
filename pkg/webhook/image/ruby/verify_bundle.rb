# frozen_string_literal: true

require 'bundler'
require 'rubygems'

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
  spec.runtime_dependencies.map { |dependency| [dependency.name, dependency.requirement.to_s] }.sort
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

def normalized_requirements(requirements)
  requirements.flat_map { |value| Gem::Requirement.new(value).requirements }
              .map { |operator, version| "#{operator} #{version}" }.uniq.sort
end

def verify_helper_policies(specs, configured)
  configured.each do |name, requirements|
    actual = specs.flat_map(&:runtime_dependencies).select { |dependency| dependency.name == name }
                  .flat_map { |dependency| dependency.requirement.requirements }
                  .map { |operator, version| "#{operator} #{version}" }.uniq.sort
    raise "#{name} compatibility policy differs from upstream" unless actual == normalized_requirements(requirements)
  end
end

root, lockfile, revision_file = ARGV
require File.join(root, 'beyla', 'compatibility')

specs = installed_specs(root)
parser = Bundler::LockfileParser.new(File.read(lockfile))
upstream = find_spec(specs, 'opentelemetry-auto-instrumentation')

verify_revision(lockfile, revision_file)
verify_installed_versions(specs, parser)
verify_upstream_dependencies(upstream, parser)
verify_ruby_policy(upstream, Beyla::OpenTelemetry::Compatibility::MINIMUM_RUBY_VERSION)
verify_rails_policy(root, Beyla::OpenTelemetry::Compatibility::MINIMUM_RAILS_VERSION)
verify_helper_policies(specs, Beyla::OpenTelemetry::Compatibility::DEPENDENCY_REQUIREMENTS)
