# frozen_string_literal: true

module Beyla
  module OpenTelemetry
    module OpenTelemetryGuard
      module_function

      def rejection(snapshot, rubyopt, entrypoint, loaded_features = $LOADED_FEATURES)
        return 'OpenTelemetry is already loaded' if loaded?(loaded_features, entrypoint)
        return 'the application bundle declares OpenTelemetry gems' if bundled?(snapshot)
        return 'RUBYOPT already preloads OpenTelemetry' if preloaded?(rubyopt, entrypoint)
      end

      def loaded?(loaded_features, entrypoint)
        loaded_features.any? do |feature|
          feature.downcase.include?('opentelemetry') && !same_feature?(feature, entrypoint)
        end
      end

      def bundled?(snapshot)
        snapshot && snapshot.direct_dependencies.any? do |name|
          name == 'opentelemetry' || name.start_with?('opentelemetry-')
        end
      end

      def preloaded?(rubyopt, entrypoint)
        required_features(rubyopt).any? do |feature|
          feature.downcase.include?('opentelemetry') && !same_feature?(feature, entrypoint)
        end
      end

      def required_features(rubyopt)
        tokens = rubyopt.to_s.split
        tokens.each_with_index.filter_map do |token, index|
          if token == '-r'
            tokens[index + 1]
          elsif token.start_with?('-r') && token.length > 2
            token[2..]
          end
        end.compact
      end

      def same_feature?(feature, entrypoint)
        normalize(feature) == normalize(entrypoint)
      end

      def normalize(path)
        File.expand_path(path.sub(/\.rb\z/, ''))
      end
    end
  end
end
