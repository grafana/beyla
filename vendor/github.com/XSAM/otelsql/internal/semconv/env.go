// Copyright Sam Xie
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

package semconv

import (
	"os"
	"strings"
)

// OTelSemConvStabilityOptIn is an environment variable.
// It can be set to "database/dup" to emit both the old and the stable database conventions,
// allowing for a seamless transition.
//
// https://opentelemetry.io/docs/specs/semconv/database/
const OTelSemConvStabilityOptIn = "OTEL_SEMCONV_STABILITY_OPT_IN"

// OTelSemConvStabilityOptInType represents the type of semantic convention stability opt-in.
type OTelSemConvStabilityOptInType int

const (
	// OTelSemConvStabilityOptInNone indicates no opt-in.
	// This is the default behavior. It only emits the old database semantic conventions.
	OTelSemConvStabilityOptInNone OTelSemConvStabilityOptInType = iota
	// OTelSemConvStabilityOptInDup indicates to emit both old and new stable database conventions.
	OTelSemConvStabilityOptInDup
	// OTelSemConvStabilityOptInStable indicates to only emit new stable database conventions.
	OTelSemConvStabilityOptInStable
)

// ParseOTelSemConvStabilityOptIn reads the OTEL_SEMCONV_STABILITY_OPT_IN environment variable
// and returns the corresponding OTelSemConvStabilityOptInType value based on its content.
// It prioritizes checking for "database/dup" before "database" to determine the opt-in type.
func ParseOTelSemConvStabilityOptIn() OTelSemConvStabilityOptInType {
	if v := os.Getenv(OTelSemConvStabilityOptIn); v != "" {
		// Check for database/dup first as it has higher precedence
		if containsValue(v, "database/dup") {
			return OTelSemConvStabilityOptInDup
		}
		// Then check for database
		if containsValue(v, "database") {
			return OTelSemConvStabilityOptInStable
		}
	}

	return OTelSemConvStabilityOptInNone
}

// containsValue checks if a comma-separated string contains a specific value.
func containsValue(list, value string) bool {
	values := strings.Split(list, ",")
	for _, item := range values {
		if strings.TrimSpace(item) == value {
			return true
		}
	}

	return false
}
