// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"

import (
	"errors"
)

// ErrProtocolMismatch indicates that parsing failed due to a protocol version
// mismatch. This is used internally to trigger fallback from MQTT 3.1.1 to
// MQTT 5.0 parsing when streaming validation detects an incompatible format.
var ErrProtocolMismatch = errors.New("MQTT protocol version mismatch")
