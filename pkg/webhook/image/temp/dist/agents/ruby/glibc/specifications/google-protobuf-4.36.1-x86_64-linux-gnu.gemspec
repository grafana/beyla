# -*- encoding: utf-8 -*-
# stub: google-protobuf 4.36.1 x86_64-linux-gnu lib

Gem::Specification.new do |s|
  s.name = "google-protobuf".freeze
  s.version = "4.36.1".freeze
  s.platform = "x86_64-linux-gnu".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 3.3.22".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "source_code_uri" => "https://github.com/protocolbuffers/protobuf/tree/v4.36.1/ruby" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Protobuf Authors".freeze]
  s.date = "2026-08-31"
  s.description = "Protocol Buffers are Google's data interchange format.".freeze
  s.email = "protobuf@googlegroups.com".freeze
  s.homepage = "https://developers.google.com/protocol-buffers".freeze
  s.licenses = ["BSD-3-Clause".freeze]
  s.required_ruby_version = Gem::Requirement.new([">= 3.2".freeze, "< 4.1.dev".freeze])
  s.rubygems_version = "4.0.3".freeze
  s.summary = "Protocol Buffers".freeze

  s.installed_by_version = "3.5.22".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<bigdecimal>.freeze, [">= 0".freeze])
  s.add_runtime_dependency(%q<rake>.freeze, ["~> 13.3".freeze])
  s.add_development_dependency(%q<ffi>.freeze, ["~> 1".freeze])
  s.add_development_dependency(%q<ffi-compiler>.freeze, ["~> 1".freeze])
  s.add_development_dependency(%q<rake-compiler>.freeze, ["~> 1.3".freeze])
  s.add_development_dependency(%q<rake-compiler-dock>.freeze, ["~> 1.11".freeze])
  s.add_development_dependency(%q<test-unit>.freeze, ["~> 3.7".freeze])
end
