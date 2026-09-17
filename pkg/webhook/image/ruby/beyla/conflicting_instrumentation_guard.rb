# frozen_string_literal: true

require_relative 'required_features'

module Beyla
  module OpenTelemetry
    module ConflictingInstrumentationGuard
      INSTRUMENTATION_GEMS = {
        'datadog' => 'Datadog',
        'ddtrace' => 'Datadog',
        'newrelic-infinite_tracing' => 'New Relic',
        'newrelic_rpm' => 'New Relic',
        'onesdk_ruby' => 'Dynatrace'
      }.freeze

      FEATURE_PATTERNS = {
        'Datadog' => [
          /(?:\A|[\/.\-])datadog(?:\z|[\/.\-])/i,
          /(?:\A|[\/.\-])ddtrace(?:\z|[\/.\-])/i
        ],
        'Dynatrace' => [/(?:\A|[\/.\-])onesdk_ruby(?:\z|[\/.\-])/i],
        'New Relic' => [
          /(?:\A|[\/.\-])new_relic(?:\z|[\/.\-])/i,
          /(?:\A|[\/.\-])newrelic(?:\z|[\/.\-])/i,
          /(?:\A|[\/.\-])newrelic_rpm(?:\z|[\/.\-])/i
        ]
      }.freeze

      module_function

      def rejection(snapshot, rubyopt, loaded_features = $LOADED_FEATURES)
        vendor = vendor_in(loaded_features)
        return "#{vendor} Ruby instrumentation is already loaded" if vendor

        gem = instrumentation_gem(snapshot)
        return "#{INSTRUMENTATION_GEMS.fetch(gem)} Ruby instrumentation dependency #{gem} is present" if gem

        vendor = vendor_in(RequiredFeatures.parse(rubyopt))
        return "#{vendor} Ruby instrumentation is preloaded by RUBYOPT" if vendor
      end

      def instrumentation_gem(snapshot)
        return unless snapshot

        INSTRUMENTATION_GEMS.each_key.find { |name| snapshot.detected?(name) }
      end

      def vendor_in(features)
        FEATURE_PATTERNS.each do |vendor, patterns|
          return vendor if features.any? { |feature| patterns.any? { |pattern| pattern.match?(feature) } }
        end

        nil
      end
    end
  end
end
