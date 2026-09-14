# Copyright The OpenTelemetry Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

OTEL_PYTHON_SYSTEM_METRICS_EXCLUDED_METRICS = (
    "OTEL_PYTHON_SYSTEM_METRICS_EXCLUDED_METRICS"
)
"""
.. envvar:: OTEL_PYTHON_SYSTEM_METRICS_EXCLUDED_METRICS

Specifies which system and process metrics should be excluded from collection
when using the default configuration. The value should be provided as a
comma separated list of glob patterns that match metric names to exclude.

**Example Usage:**

To exclude all CPU related metrics and specific process metrics:

.. code:: bash

    export OTEL_PYTHON_SYSTEM_METRICS_EXCLUDED_METRICS="system.cpu.*,process.memory.*"

To exclude a specific metric:

.. code:: bash

    export OTEL_PYTHON_SYSTEM_METRICS_EXCLUDED_METRICS="system.network.io"

**Supported Glob Patterns:**

The environment variable supports standard glob patterns for metric filtering:

- ``*`` - Matches any sequence of characters within a metric name

**Example Patterns:**

- ``system.*`` - Exclude all system metrics
- ``process.cpu.*`` - Exclude all process CPU related metrics
- ``*.utilization`` - Exclude all utilization metrics
- ``system.memory.usage`` - Exclude the system memory usage metric

"""
