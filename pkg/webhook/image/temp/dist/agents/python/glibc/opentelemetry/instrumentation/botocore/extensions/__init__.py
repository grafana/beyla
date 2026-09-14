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

import importlib
import logging

_logger = logging.getLogger(__name__)


def _lazy_load(module, cls):
    def loader():
        imported_mod = importlib.import_module(module, __name__)
        return getattr(imported_mod, cls, None)

    return loader


_BOTOCORE_EXTENSIONS = {
    "bedrock-runtime": _lazy_load(".bedrock", "_BedrockRuntimeExtension"),
    "dynamodb": _lazy_load(".dynamodb", "_DynamoDbExtension"),
    "lambda": _lazy_load(".lmbd", "_LambdaExtension"),
    "secretsmanager": _lazy_load(
        ".secretsmanager", "_SecretsManagerExtension"
    ),
    "stepfunctions": _lazy_load(".sfns", "_StepFunctionsExtension"),
    "sns": _lazy_load(".sns", "_SnsExtension"),
    "sqs": _lazy_load(".sqs", "_SqsExtension"),
}

_AIOBOTOCORE_EXTENSIONS = {
    # TODO: Add Bedrock support for aiobotocore
    "dynamodb": _lazy_load(".dynamodb", "_DynamoDbExtension"),
    "lambda": _lazy_load(".lmbd", "_LambdaExtension"),
    "secretsmanager": _lazy_load(
        ".secretsmanager", "_SecretsManagerExtension"
    ),
    "stepfunctions": _lazy_load(".sfns", "_StepFunctionsExtension"),
    "sns": _lazy_load(".sns", "_SnsExtension"),
    "sqs": _lazy_load(".sqs", "_SqsExtension"),
}
