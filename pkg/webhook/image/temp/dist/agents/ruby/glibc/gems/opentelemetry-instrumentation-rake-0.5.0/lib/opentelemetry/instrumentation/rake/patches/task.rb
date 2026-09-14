# frozen_string_literal: true

module OpenTelemetry
  module Instrumentation
    module Rake
      module Patches
        # Module to prepend to Rask::Task for instrumentation
        module Task
          def invoke(*args)
            tracer.in_span('rake.invoke', attributes: { 'rake.task' => name }) do
              super
            end
          ensure
            force_flush
          end

          def execute(args = nil)
            tracer.in_span('rake.execute', attributes: { 'rake.task' => name }) do
              super
            end
          ensure
            force_flush
          end

          private

          def tracer
            Rake::Instrumentation.instance.tracer
          end

          def force_flush
            top_level_task_names = ::Rake.application.top_level_tasks.map { |t| t.split('[').first }

            return unless top_level_task_names.include?(name)

            OpenTelemetry.tracer_provider.force_flush
          end
        end
      end
    end
  end
end
