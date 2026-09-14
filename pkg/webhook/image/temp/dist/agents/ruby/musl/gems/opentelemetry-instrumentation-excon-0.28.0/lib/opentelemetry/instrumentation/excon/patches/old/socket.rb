# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Excon
      module Patches
        module Old
          # Module to prepend to an Excon Socket for instrumentation
          module Socket
            private

            def connect
              return super if untraced?

              if @data[:proxy]
                conn_address = @data.dig(:proxy, :hostname)
                conn_port = @data.dig(:proxy, :port)
              else
                conn_address = @data[:hostname]
                conn_port = @port
              end

              attributes = { OpenTelemetry::SemanticConventions::Trace::NET_PEER_NAME => conn_address, OpenTelemetry::SemanticConventions::Trace::NET_PEER_PORT => conn_port }.merge!(OpenTelemetry::Common::HTTP::ClientContext.attributes)

              if is_a?(::Excon::SSLSocket) && @data[:proxy]
                span_name = 'HTTP CONNECT'
                span_kind = :client
              else
                span_name = 'connect'
                span_kind = :internal
              end

              tracer.in_span(span_name, attributes: attributes, kind: span_kind) do
                super
              end
            end

            def tracer
              Excon::Instrumentation.instance.tracer
            end

            def untraced?
              address = if @data[:proxy]
                          @data.dig(:proxy, :hostname)
                        else
                          @data[:hostname]
                        end

              Excon::Instrumentation.instance.untraced?(address)
            end
          end
        end
      end
    end
  end
end
