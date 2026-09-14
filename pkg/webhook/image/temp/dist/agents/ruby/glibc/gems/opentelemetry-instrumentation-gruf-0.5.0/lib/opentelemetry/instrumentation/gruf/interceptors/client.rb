# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Gruf
      module Interceptors
        class Client < ::Gruf::Interceptors::ClientInterceptor
          def call(request_context:)
            return yield if instrumentation_config.empty?

            service = request_context.method.split('/')[1]
            method = request_context.method_name
            method_name_with_service = [service.underscore, method].join('.').downcase

            return yield if instrumentation_config[:grpc_ignore_methods_on_client].include?(method_name_with_service)

            metadata = request_context.metadata
            attributes = {
              OpenTelemetry::SemanticConventions::Trace::RPC_SYSTEM => 'grpc',
              OpenTelemetry::SemanticConventions::Trace::RPC_SERVICE => service,
              OpenTelemetry::SemanticConventions::Trace::RPC_METHOD => method,
              OpenTelemetry::SemanticConventions::Trace::PEER_SERVICE => instrumentation_config[:peer_service],
              'rpc.type' => request_context.type.to_s,
              'net.sock.peer.addr' => request_context.call.instance_variable_get(:@wrapped)&.peer
            }.compact

            attributes.merge!(allowed_metadata_headers(metadata.transform_keys(&:to_s)))

            instrumentation_tracer.in_span(
              request_context.method.to_s,
              attributes: attributes,
              kind: OpenTelemetry::Trace::SpanKind::CLIENT
            ) do |span|
              OpenTelemetry.propagation.inject(metadata)
              yield.tap do
                span&.set_attribute(OpenTelemetry::SemanticConventions::Trace::RPC_GRPC_STATUS_CODE, 0)
              end
            rescue StandardError => e
              span&.set_attribute(OpenTelemetry::SemanticConventions::Trace::RPC_GRPC_STATUS_CODE, e.code)
              raise e
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
