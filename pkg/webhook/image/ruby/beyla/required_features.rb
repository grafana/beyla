# frozen_string_literal: true

module Beyla
  module OpenTelemetry
    module RequiredFeatures
      module_function

      def parse(options)
        tokens = options.to_s.split
        tokens.each_with_index.filter_map do |token, index|
          if token == '-r'
            tokens[index + 1]
          elsif token.start_with?('-r') && token.length > 2
            token[2..]
          end
        end.compact
      end
    end
  end
end
