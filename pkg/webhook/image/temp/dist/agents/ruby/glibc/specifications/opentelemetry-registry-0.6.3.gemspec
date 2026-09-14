# -*- encoding: utf-8 -*-
# stub: opentelemetry-registry 0.6.3 ruby lib

Gem::Specification.new do |s|
  s.name = "opentelemetry-registry".freeze
  s.version = "0.6.3".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/open-telemetry/opentelemetry-ruby/issues", "changelog_uri" => "https://rubydoc.info/gems/opentelemetry-registry/0.6.3/file/CHANGELOG.md", "documentation_uri" => "https://rubydoc.info/gems/opentelemetry-registry/0.6.3", "source_code_uri" => "https://github.com/open-telemetry/opentelemetry-ruby/tree/opentelemetry-registry/v0.6.3/registry" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["OpenTelemetry Authors".freeze]
  s.date = "1980-01-02"
  s.description = "Registry for the OpenTelemetry Instrumentation Libraries".freeze
  s.email = ["cncf-opentelemetry-contributors@lists.cncf.io".freeze]
  s.homepage = "https://github.com/open-telemetry/opentelemetry-ruby".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3".freeze)
  s.rubygems_version = "4.0.10".freeze
  s.summary = "Registry for the OpenTelemetry Instrumentation Libraries".freeze

  s.installed_by_version = "3.5.22".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<opentelemetry-api>.freeze, ["~> 1.1".freeze])
end
