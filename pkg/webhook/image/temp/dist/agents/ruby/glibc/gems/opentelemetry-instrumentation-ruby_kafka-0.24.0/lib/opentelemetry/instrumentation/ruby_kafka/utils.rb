# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module RubyKafka
      # Utilities to help with instrumenting kafka
      module Utils
        module_function

        def extract_message_key(key)
          # skip encode if already valid utf8
          return key if key.nil? || (key.encoding == Encoding::UTF_8 && key.valid_encoding?)

          key.encode(Encoding::UTF_8)
        rescue Encoding::UndefinedConversionError
          nil
        end
      end
    end
  end
end
