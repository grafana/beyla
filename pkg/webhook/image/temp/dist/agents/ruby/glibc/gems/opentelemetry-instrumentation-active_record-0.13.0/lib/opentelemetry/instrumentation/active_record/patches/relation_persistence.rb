# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveRecord
      module Patches
        # Module to prepend to ActiveRecord::Relation for instrumentation
        module RelationPersistence
          def update_all(...)
            tracer.in_span("#{model.name}.update_all") do
              super
            end
          end

          def delete_all(...)
            tracer.in_span("#{model.name}.delete_all") do
              super
            end
          end

          private

          def tracer
            ActiveRecord::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
