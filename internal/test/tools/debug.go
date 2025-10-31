// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"fmt"
)

// ToJSON is just a one-line convenience method to provide some debug data
// in tests, without having to deal with error handling nor byte-to-string transformation
func ToJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("converting %+v to JSON: %s", v, err.Error()))
	}
	return string(b)
}
