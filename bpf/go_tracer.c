//go:build beyla_bpf_ignore
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "go_runtime.h"
#include "go_nethttp.h"
#include "go_sql.h"
#include "go_grpc.h"
#include "go_redis.h"
#include "go_kafka_go.h"
#include "go_sarama.h"
