// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration // import "go.opentelemetry.io/obi/pkg/test/integration"

import "time"

const (
	instrumentedServiceStdURL = "http://localhost:8080"
	testTimeout               = 60 * time.Second
)
