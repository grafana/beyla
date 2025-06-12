//go:build obi_bpf_ignore
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

#include "go_runtime.c"
#include "go_nethttp.c"
#include "go_sql.c"
#include "go_grpc.c"
#include "go_redis.c"
#include "go_kafka_go.c"
#include "go_sarama.c"
