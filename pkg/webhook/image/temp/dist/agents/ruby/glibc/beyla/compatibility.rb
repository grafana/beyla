# frozen_string_literal: true

module Beyla
  module OpenTelemetry
    module Compatibility
      MINIMUM_RUBY_VERSION = '3.3'
      MINIMUM_RAILS_VERSION = '7.1'
      DEPENDENCY_REQUIREMENTS = {
        'google-protobuf' => ['>= 3.18', '< 5.0', '~> 4.26'],
        'googleapis-common-protos-types' => ['~> 1.3']
      }.freeze
    end
  end
end
