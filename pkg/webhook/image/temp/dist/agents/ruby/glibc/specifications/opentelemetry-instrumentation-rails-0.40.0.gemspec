# -*- encoding: utf-8 -*-
# stub: opentelemetry-instrumentation-rails 0.40.0 ruby lib

Gem::Specification.new do |s|
  s.name = "opentelemetry-instrumentation-rails".freeze
  s.version = "0.40.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "source_code_uri" => "https://github.com/open-telemetry/opentelemetry-ruby-contrib/tree/main/instrumentation/rails" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["OpenTelemetry Authors".freeze]
  s.date = "1980-01-02"
  s.description = "Rails instrumentation for the OpenTelemetry framework".freeze
  s.email = ["cncf-opentelemetry-contributors@lists.cncf.io".freeze]
  s.homepage = "https://github.com/open-telemetry/opentelemetry-ruby-contrib".freeze
  s.licenses = ["Apache-2.0".freeze]
  s.post_install_message = "".freeze
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "4.0.3".freeze
  s.summary = "Rails instrumentation for the OpenTelemetry framework".freeze

  s.installed_by_version = "3.5.22".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<opentelemetry-instrumentation-action_mailer>.freeze, ["~> 0.6".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-action_pack>.freeze, ["~> 0.15".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-action_view>.freeze, ["~> 0.11".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-active_job>.freeze, ["~> 0.10".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-active_record>.freeze, ["~> 0.11".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-active_storage>.freeze, ["~> 0.3".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-active_support>.freeze, ["~> 0.10".freeze])
  s.add_runtime_dependency(%q<opentelemetry-instrumentation-concurrent_ruby>.freeze, ["~> 0.23".freeze])
end
