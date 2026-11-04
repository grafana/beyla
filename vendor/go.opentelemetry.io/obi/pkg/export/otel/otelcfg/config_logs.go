// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otelcfg // import "go.opentelemetry.io/obi/pkg/export/otel/otelcfg"

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"time"
)

// LogsConfig configures delivery of exception LogRecords. Config v2 sets it
// from logger_provider.
type LogsConfig struct {
	LogsExport    LogsExportFunc
	Endpoint      string
	Protocol      Protocol
	Compression   string
	BatchMaxSize  int
	QueueSize     int
	BatchTimeout  time.Duration
	InjectHeaders func(map[string]string)
}

func (c *LogsConfig) Enabled() bool {
	return c.LogsExport != nil || c.Endpoint != "" || c.Protocol == ProtocolDebug
}

func (c *LogsConfig) Headers() map[string]string {
	headers := map[string]string{}
	if c.InjectHeaders != nil {
		c.InjectHeaders(headers)
	}
	maps.Copy(headers, HeadersFromEnv(envHeaders))
	maps.Copy(headers, HeadersFromEnv("OTEL_EXPORTER_OTLP_LOGS_HEADERS"))
	return headers
}

func (c *LogsConfig) Validate() error {
	if !c.Enabled() {
		return nil
	}
	if c.BatchMaxSize <= 0 || c.QueueSize < 2*c.BatchMaxSize || c.BatchTimeout <= 0 {
		return errors.New("logger_provider batch processor requires positive max_export_batch_size and schedule_delay, and max_queue_size >= 2 * max_export_batch_size")
	}
	if c.LogsExport != nil || c.Protocol == ProtocolDebug {
		return nil
	}
	switch c.Protocol {
	case ProtocolGRPC, ProtocolHTTPProtobuf:
	default:
		return fmt.Errorf("unsupported logs protocol %q", c.Protocol)
	}
	if addr, ok := unixSocketEndpoint(c.Endpoint); ok {
		return validateUnixSocketAddr(addr)
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("logger_provider exporter endpoint must be an http, https or unix URL")
	}
	return nil
}

// UnixSocket returns the socket address and gRPC target for a Unix endpoint.
func (c *LogsConfig) UnixSocket() (address, target string) {
	if addr, ok := unixSocketEndpoint(c.Endpoint); ok {
		return addr, grpcUnixTarget(addr)
	}
	return "", ""
}
