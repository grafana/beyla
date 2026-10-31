// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
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

func ec2NodeFetcher(ctx context.Context) (NodeMeta, error) {
	node, err := otelNodeFetcher(ClusterEC2, newEC2Detector())(ctx)
	if err != nil || !node.Features.Has(ClusterEC2) {
		return node, err
	}
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()
	node.EC2VPCID, err = ec2VPCID(ctx)
	if err != nil {
		nslog().Debug("can't detect EC2 VPC; skipping private DNS discovery", "error", err)
	}
	return node, nil
}

func ec2VPCID(ctx context.Context) (string, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithLogger(ec2SDKLogger(nslog())))
	if err != nil {
		return "", err
	}
	client := imds.NewFromConfig(cfg)
	read := func(path string) (string, error) {
		out, err := client.GetMetadata(ctx, &imds.GetMetadataInput{Path: path})
		if err != nil {
			return "", err
		}
		defer out.Content.Close()
		value, err := io.ReadAll(out.Content)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(value)), nil
	}
	mac, err := read("mac")
	if err != nil || mac == "" {
		return "", err
	}
	return read("network/interfaces/macs/" + mac + "/vpc-id")
}
