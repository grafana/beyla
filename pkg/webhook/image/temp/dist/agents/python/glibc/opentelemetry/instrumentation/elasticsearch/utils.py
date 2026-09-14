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
import json

sanitized_value = "?"


def _mask_leaf_nodes(obj):
    """
    Recursively traverses JSON structure and masks leaf node values.
    Leaf nodes are final values that are no longer dict or list.
    """
    if isinstance(obj, dict):
        return {key: _mask_leaf_nodes(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_mask_leaf_nodes(item) for item in obj]
    # Mask leaf node
    return sanitized_value


def sanitize_body(body) -> str:
    if isinstance(body, str):
        body = json.loads(body)

    masked_body = _mask_leaf_nodes(body)
    return str(masked_body)
