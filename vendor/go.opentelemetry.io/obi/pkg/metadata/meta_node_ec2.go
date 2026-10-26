// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/smithy-go/logging"

	"go.opentelemetry.io/contrib/detectors/aws/ec2/v2"
	"go.opentelemetry.io/otel/sdk/resource"
)

// ec2SDKLog forwards AWS SDK log lines to logger.
type ec2SDKLog struct {
	logger *slog.Logger
	ctx    context.Context
}

var _ logging.ContextLogger = ec2SDKLog{}

func ec2SDKLogger(logger *slog.Logger) logging.Logger {
	return ec2SDKLog{logger: logger}
}

func (l ec2SDKLog) WithContext(ctx context.Context) logging.Logger {
	if ctx == nil {
		ctx = context.Background()
	}
	l.ctx = ctx
	return l
}

func (l ec2SDKLog) Logf(classification logging.Classification, format string, args ...any) {
	var level slog.Level
	switch classification {
	case logging.Warn:
		level = slog.LevelWarn
	case logging.Debug:
		level = slog.LevelDebug
	default:
		level = slog.LevelInfo
	}
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if !l.logger.Enabled(ctx, level) {
		return
	}
	l.logger.Log(ctx, level, fmt.Sprintf(format, args...))
}

func newEC2Detector() resource.Detector {
	return ec2.NewResourceDetectorWithOptions(
		ec2.WithAWSLogger(ec2SDKLogger(slog.With("component", "meta.NodeMeta.ec2"))),
	)
}
