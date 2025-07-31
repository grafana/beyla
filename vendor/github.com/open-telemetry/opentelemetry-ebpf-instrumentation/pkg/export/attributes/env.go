// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"strings"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/util"
)

type VarHandler func(k string, v string)

func ParseOTELResourceVariable(envVar string, handler VarHandler) {
	variables := util.NewSplitIterator(envVar, ",")

	for {
		variable, eof := variables.Next()

		if eof {
			break
		}

		variable = strings.TrimSuffix(variable, ",")

		key, value, found := strings.Cut(variable, "=")

		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if key == "" || value == "" {
			continue
		}

		handler(key, value)
	}
}
