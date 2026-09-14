# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module ActiveRecord
      module Patches
        # Module to prepend to ActiveRecord::Base for instrumentation
        # contains the ActiveRecord::Persistence methods to be patched
        module Persistence
          def delete
            tracer.in_span("#{self.class}#delete") do
              super
            end
          end

          def destroy
            tracer.in_span("#{self.class}#destroy") do
              super
            end
          end

          def destroy!
            tracer.in_span("#{self.class}#destroy!") do
              super
            end
          end

          def becomes(...)
            tracer.in_span("#{self.class}#becomes") do
              super
            end
          end

          def becomes!(...)
            tracer.in_span("#{self.class}#becomes!") do
              super
            end
          end

          def update_attribute(...)
            tracer.in_span("#{self.class}#update_attribute") do
              super
            end
          end

          def update(...)
            tracer.in_span("#{self.class}#update") do
              super
            end
          end

          def update!(...)
            tracer.in_span("#{self.class}#update!") do
              super
            end
          end

          def update_column(...)
            tracer.in_span("#{self.class}#update_column") do
              super
            end
          end

          def update_columns(...)
            tracer.in_span("#{self.class}#update_columns") do
              super
            end
          end

          def increment(...)
            tracer.in_span("#{self.class}#increment") do
              super
            end
          end

          def increment!(...)
            tracer.in_span("#{self.class}#increment!") do
              super
            end
          end

          def decrement(...)
            tracer.in_span("#{self.class}#decrement") do
              super
            end
          end

          def decrement!(...)
            tracer.in_span("#{self.class}#decrement!") do
              super
            end
          end

          def toggle(...)
            tracer.in_span("#{self.class}#toggle") do
              super
            end
          end

          def toggle!(...)
            tracer.in_span("#{self.class}#toggle!") do
              super
            end
          end

          def reload(...)
            tracer.in_span("#{self.class}#reload") do
              super
            end
          end

          def touch(...)
            tracer.in_span("#{self.class}#touch") do
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
