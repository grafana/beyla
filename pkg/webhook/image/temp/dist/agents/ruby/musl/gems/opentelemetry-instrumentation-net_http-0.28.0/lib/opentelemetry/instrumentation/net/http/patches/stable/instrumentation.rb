# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

module OpenTelemetry
  module Instrumentation
    module Net
      module HTTP
        module Patches
          module Stable
            # Module to prepend to Net::HTTP for instrumentation
            module Instrumentation
              USE_SSL_TO_SCHEME = { false => 'http', true => 'https' }.freeze

              # Constant for the HTTP status range
              HTTP_STATUS_SUCCESS_RANGE = (100..399)

              def request(req, body = nil, &)
                # Do not trace recursive call for starting the connection
                return super unless started?

                return super if untraced?

                span_data = HttpHelper.span_attrs_for_stable(req.method)

                attributes = { 'url.scheme' => USE_SSL_TO_SCHEME[use_ssl?],
                               'server.address' => @address,
                               'server.port' => @port }
                path, query = split_path_and_query(req.path)
                attributes['url.path'] = path
                attributes['url.query'] = query if query

                attributes.merge!(span_data.attributes)

                tracer.in_span(
                  span_data.span_name,
                  attributes: attributes,
                  kind: :client
                ) do |span|
                  OpenTelemetry.propagation.inject(req)

                  super.tap do |response|
                    annotate_span_with_response!(span, response)
                  end
                end
              end

              private

              def connect
                return super if untraced?

                if proxy?
                  conn_address = proxy_address
                  conn_port    = proxy_port
                else
                  conn_address = address
                  conn_port    = port
                end

                attributes = {
                  'server.address' => conn_address,
                  'server.port' => conn_port
                }.merge!(OpenTelemetry::Common::HTTP::ClientContext.attributes)

                if use_ssl? && proxy?
                  span_name = 'CONNECT'
                  span_kind = :client
                else
                  span_name = 'connect'
                  span_kind = :internal
                end

                tracer.in_span(span_name, attributes: attributes, kind: span_kind) do
                  super
                end
              end

              def annotate_span_with_response!(span, response)
                return unless response&.code

                status_code = response.code.to_i

                span.set_attribute('http.response.status_code', status_code)
                span.status = OpenTelemetry::Trace::Status.error unless HTTP_STATUS_SUCCESS_RANGE.cover?(status_code)
              end

              def tracer
                Net::HTTP::Instrumentation.instance.tracer
              end

              def untraced?
                untraced_context? || untraced_host?
              end

              def untraced_host?
                return true if Net::HTTP::Instrumentation.instance.config[:untraced_hosts]&.any? do |host|
                  host.is_a?(Regexp) ? host.match?(@address) : host == @address
                end

                false
              end

              def untraced_context?
                OpenTelemetry::Common::Utilities.untraced?
              end

              def split_path_and_query(path)
                path_and_query = path.split('?')

                [path_and_query[0], path_and_query[1]]
              end
            end
          end
        end
      end
    end
  end
end
