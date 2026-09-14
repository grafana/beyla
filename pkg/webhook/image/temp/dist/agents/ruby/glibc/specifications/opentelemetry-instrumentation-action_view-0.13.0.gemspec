# -*- encoding: utf-8 -*-
# stub: opentelemetry-instrumentation-action_view 0.13.0 ruby lib

Gem::Specification.new do |s|
  s.name = "opentelemetry-instrumentation-action_view".freeze
  s.version = "0.13.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/open-telemetry/opentelemetry-ruby-contrib/issues", "changelog_uri" => "https://rubydoc.info/gems/opentelemetry-instrumentation-action_view/0.13.0/file/CHANGELOG.md", "documentation_uri" => "https://rubydoc.info/gems/opentelemetry-instrumentation-action_view/0.13.0", "source_code_uri" => "https://github.com/open-telemetry/opentelemetry-ruby-contrib/tree/opentelemetry-instrumentation-action_view/v0.13.0/instrumentation/action_view" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["OpenTelemetry Authors".freeze]
  s.date = "1980-01-02"
  s.description = "ActionView instrumentation for the OpenTelemetry framework".freeze
  s.email = ["cncf-opentelemetry-contributors@lists.cncf.io".freeze]
  s.homepage = "https://github.com/open-telemetry/opentelemetry-ruby-contrib".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3".freeze)
  s.rubygems_version = "4.0.6".freeze
  s.summary = "ActionView instrumentation for the OpenTelemetry framework".freeze

  s.installed_by_version = "3.5.22".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<opentelemetry-instrumentation-active_support>.freeze, ["~> 0.10".freeze])
end
