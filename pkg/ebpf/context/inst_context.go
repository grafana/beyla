// Copyright The OpenTelemetry Authors
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

package context

import (
	"github.com/cilium/ebpf/link"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/inject"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/process"
)

type InstrumentorContext struct {
	TargetDetails *process.TargetDetails
	Executable    *link.Executable
	Injector      *inject.Injector
}
