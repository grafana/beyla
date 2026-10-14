// Copyright The OpenTelemetry Authors
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

// This implementation was inspired by the code in
// https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/cdfad4a67b86c282ed29141ca0b3bca46509eee9/internal/pkg/opentelemetry/id_generator.go

package idgen // import "go.opentelemetry.io/obi/pkg/export/otel/idgen"

import (
	"encoding/binary"
	"math/rand/v2"

	"go.opentelemetry.io/otel/trace"
)

func RandomTraceID() trace.TraceID {
	t := trace.TraceID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

func RandomSpanID() trace.SpanID {
	t := trace.SpanID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}
