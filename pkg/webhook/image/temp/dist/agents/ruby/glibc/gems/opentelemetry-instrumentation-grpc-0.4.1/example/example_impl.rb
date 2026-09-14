# frozen_string_literal: true

# Copyright The OpenTelemetry Authors
#
# SPDX-License-Identifier: Apache-2.0

class ExampleImpl < ::Proto::Example::ExampleAPI::Service
  def example(_req, _call)
    Proto::Example::ExampleResponse.new(response_name: 'Hello')
  end
end
