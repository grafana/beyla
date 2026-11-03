// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"errors"
	"time"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

func applyV2LoggerProvider(cfg *obi.Config, p *otelconfx.LoggerProvider) error {
	if p == nil {
		return nil
	}
	const path = "logger_provider"
	if p.Limits != nil || p.LoggerConfiguratorDevelopment != nil {
		return unsupportedV2Field(path + " limits or logger_configurator/development")
	}
	if len(p.Processors) != 1 {
		return errors.New("logger_provider.processors must contain exactly one batch processor")
	}
	proc := p.Processors[0]
	if proc.Batch == nil || proc.Simple != nil || !zeroValue(proc.AdditionalProperties) {
		return unsupportedV2Field(path + ".processors[0]")
	}
	b := proc.Batch
	if b.ExportTimeout != nil {
		return unsupportedV2Field(path + ".processors[0].batch.export_timeout")
	}
	exp := b.Exporter
	if exp.OTLPFileDevelopment != nil || len(exp.Console) != 0 || !zeroValue(exp.AdditionalProperties) || countTrue(exp.OTLPGrpc != nil, exp.OTLPHttp != nil, exp.Console != nil) != 1 {
		return unsupportedV2Field(path + ".processors[0].batch.exporter")
	}
	const exporterPath = "logger_provider.processors[0].batch.exporter"
	if exp.Console != nil {
		cfg.Logs.Protocol = otelcfg.ProtocolDebug
	} else if e := exp.OTLPGrpc; e != nil {
		if e.Timeout != nil {
			return unsupportedV2Field(exporterPath + ".otlp_grpc.timeout")
		}
		if err := validateGrpcTLS(e.Tls, exporterPath+".otlp_grpc.tls"); err != nil {
			return err
		}
		inject, err := headerInjector(e.Headers, e.HeadersList, exporterPath)
		if err != nil {
			return err
		}
		cfg.Logs.Endpoint = grpcEndpoint(e.Endpoint, e.Tls, defaultOTLPGRPCEndpoint)
		cfg.Logs.Protocol = otelcfg.ProtocolGRPC
		cfg.Logs.InjectHeaders = inject
		if e.Compression != nil {
			cfg.Logs.Compression = *e.Compression
		}
	} else {
		e := exp.OTLPHttp
		if e.Timeout != nil {
			return unsupportedV2Field(exporterPath + ".otlp_http.timeout")
		}
		if err := validateHTTPTLS(e.Tls, exporterPath+".otlp_http.tls"); err != nil {
			return err
		}
		protocol, err := httpProtocol(e.Encoding, exporterPath+".otlp_http.encoding")
		if err != nil {
			return err
		}
		inject, err := headerInjector(e.Headers, e.HeadersList, exporterPath)
		if err != nil {
			return err
		}
		cfg.Logs.Endpoint = optionalEndpoint(e.Endpoint, "http://localhost:4318/v1/logs")
		cfg.Logs.Protocol = protocol
		cfg.Logs.InjectHeaders = inject
		if e.Compression != nil {
			cfg.Logs.Compression = *e.Compression
		}
	}
	if b.MaxQueueSize != nil {
		cfg.Logs.QueueSize = *b.MaxQueueSize
	}
	if b.MaxExportBatchSize != nil {
		cfg.Logs.BatchMaxSize = *b.MaxExportBatchSize
	}
	if b.ScheduleDelay != nil {
		cfg.Logs.BatchTimeout = time.Duration(*b.ScheduleDelay) * time.Millisecond
	}
	return cfg.Logs.Validate()
}
