# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

require_relative '../middlewares/tracer_middleware'

module OpenTelemetry
  module Instrumentation
    module Sinatra
      module Extensions
        # Sinatra extension that installs TracerMiddleware and provides
        # tracing for template rendering
        module TracerExtension
          # Constants patches for `render` method
          module RenderPatches
            def render(_engine, data, *)
              template_name = data.is_a?(Symbol) ? data : :literal

              Sinatra::Instrumentation.instance.tracer.in_span(
                'sinatra.render_template',
                attributes: { 'sinatra.template_name' => template_name.to_s }
              ) do
                super
              end
            end
          end

          # Sinatra hook after extension is registered
          def self.registered(app)
            # Create tracing `render` method
            ::Sinatra::Base.prepend(RenderPatches)
            Sinatra::Instrumentation.instance.install_middleware(app)
          end
        end
      end
    end
  end
end
