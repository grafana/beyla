# frozen_string_literal: true

module Beyla
  module OpenTelemetry
    module Compatibility
      DEPENDENCY_REQUIREMENTS = {
        "google-protobuf" => ["< 5.0", ">= 3.18", "~> 4.26"],
        "googleapis-common-protos-types" => ["~> 1.3"],
      }.freeze
      OPENTELEMETRY_API_REQUIREMENTS = ["~> 1.0", "~> 1.1", "~> 1.2", "~> 1.7", "~> 1.9.0"].freeze
    end
  end
end
