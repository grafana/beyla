# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Gruf
      module Interceptors
        class Server < ::Gruf::Interceptors::ServerInterceptor
          def call
            return yield if instrumentation_config.empty?

            method = request.method_name

            return yield if instrumentation_config[:grpc_ignore_methods_on_server].include?(method)

            service_name = request.service.service_name.to_s
            method_name = request.method_key.to_s
            route = "/#{service_name}/#{method_name.camelize}"
            metadata = request.active_call.metadata

            attributes = {
              OpenTelemetry::SemanticConventions::Trace::RPC_SYSTEM => 'grpc',
              OpenTelemetry::SemanticConventions::Trace::RPC_SERVICE => service_name,
              OpenTelemetry::SemanticConventions::Trace::RPC_METHOD => method_name,
              OpenTelemetry::SemanticConventions::Trace::PEER_SERVICE => instrumentation_config[:peer_service],
              'net.sock.peer.addr' => request.active_call.instance_variable_get(:@wrapped)&.peer
            }.compact

            attributes.merge!(allowed_metadata_headers(metadata.transform_keys(&:to_s)))

            extracted_context = OpenTelemetry.propagation.extract(metadata)
            OpenTelemetry::Context.with_current(extracted_context) do
              instrumentation_tracer.in_span(route, attributes: attributes, kind: OpenTelemetry::Trace::SpanKind::SERVER) do |span|
                yield.tap do
                  span&.set_attribute(OpenTelemetry::SemanticConventions::Trace::RPC_GRPC_STATUS_CODE, 0)
                end
              end
            end
          end
          # rubocop:enable Metrics/MethodLength

          private

          def allowed_metadata_headers(metadata)
            instrumentation_config[:allowed_metadata_headers].each_with_object({}) do |k, h|
              if (v = metadata[k.to_s])
                h["rpc.request.metadata.#{k}"] = v
              end
            end
          end

          def instrumentation_config
            Gruf::Instrumentation.instance.config
          end

          def instrumentation_tracer
            OpenTelemetry::Instrumentation::Gruf::Instrumentation.instance.tracer
          end
        end
      end
    end
  end
end
