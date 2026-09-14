# -*- encoding: utf-8 -*-
# stub: opentelemetry-auto-instrumentation 0.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "opentelemetry-auto-instrumentation".freeze
  s.version = "0.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "bug_tracker_uri" => "https://github.com/open-telemetry/opentelemetry-ruby-instrumentation/issues", "changelog_uri" => "https://rubydoc.info/gems/opentelemetry-auto-instrumentation/0.1.0/file/CHANGELOG.md", "documentation_uri" => "https://rubydoc.info/gems/opentelemetry-auto-instrumentation/0.1.0", "source_code_uri" => "https://github.com/open-telemetry/opentelemetry-ruby-instrumentation/tree/opentelemetry-auto-instrumentation/v0.1.0/packages/auto-instrumentation" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["OpenTelemetry Authors".freeze]
  s.date = "2026-09-11"
  s.description = "Auto-instrumentation for OpenTelemetry Ruby".freeze
  s.email = ["cncf-opentelemetry-contributors@lists.cncf.io".freeze]
  s.homepage = "https://github.com/open-telemetry/opentelemetry-ruby-instrumentation".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3".freeze)
  s.rubygems_version = "3.5.22".freeze
  s.summary = "Auto-instrumentation for OpenTelemetry Ruby".freeze

  s.installed_by_version = "3.5.22".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<opentelemetry-api>.freeze, ["~> 1.9.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-exporter-otlp>.freeze, ["~> 0.33.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-exporter-otlp-logs>.freeze, ["~> 0.4.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-exporter-otlp-metrics>.freeze, ["~> 0.8.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-helpers-mysql>.freeze, ["~> 0.5.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-helpers-sql>.freeze, ["~> 0.3.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-helpers-sql-processor>.freeze, ["~> 0.4.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-all>.freeze, ["~> 0.91.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-logs-api>.freeze, ["~> 0.3.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-logs-sdk>.freeze, ["~> 0.5.1".freeze])
  s.add_runtime_dependency(%q<opentelemetry-metrics-api>.freeze, ["~> 0.5.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-metrics-sdk>.freeze, ["~> 0.13.1".freeze])
  s.add_runtime_dependency(%q<opentelemetry-resource-detector-aws>.freeze, ["~> 0.5.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-resource-detector-azure>.freeze, ["~> 0.3.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-resource-detector-container>.freeze, ["~> 0.3.0".freeze])
  s.add_runtime_dependency(%q<opentelemetry-sdk>.freeze, ["~> 1.11.0".freeze])
end
