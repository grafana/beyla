// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

func (bc *BPFCollector) enableBPFStatsRuntime() {}
