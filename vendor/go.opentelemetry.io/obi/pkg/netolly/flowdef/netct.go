// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flowdef // import "go.opentelemetry.io/obi/pkg/netolly/flowdef"

const (
	DeduperNone      = "none"
	DeduperFirstCome = "first_come"
)

type PortGuessPolicy string

const (
	PortGuessDisable = PortGuessPolicy("disable")
	PortGuessOrdinal = PortGuessPolicy("ordinal")
)
