// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package otelsdk

//go:generate wget --quiet -N -O grafana-opentelemetry-java.jar https://github.com/grafana/grafana-opentelemetry-java/releases/download/v2.13.2.1/grafana-opentelemetry-java.jar

import (
	"bufio"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/grafana/jvmtools/jvm"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

type SDKInjector struct {
	log *slog.Logger
	cfg *obi.Config
}

func NewSDKInjector(cfg *obi.Config) *SDKInjector {
	return &SDKInjector{
		cfg: cfg,
		log: slog.With("component", "otelsdk.Injector"),
	}
}

func dirOK(root, dir string) bool {
	fullDir := filepath.Join(root, dir)

	info, err := os.Stat(fullDir)
	return err == nil && info.IsDir()
}

func (i *SDKInjector) findTempDir(root string, ie *ebpf.Instrumentable) (string, error) {
	if tmpDir, ok := ie.FileInfo.Service.EnvVars["TMPDIR"]; ok {
		if dirOK(root, tmpDir) {
			return tmpDir, nil
		}
	}

	tmpDir := "/tmp"
	if dirOK(root, tmpDir) {
		return tmpDir, nil
	}

	tmpDir = "/var/tmp"
	if dirOK(root, tmpDir) {
		return tmpDir, nil
	}

	return "", errors.New("couldn't find suitable temp directory for injection")
}

func (i *SDKInjector) Enabled() bool {
	return i.cfg.EBPF.UseOTelSDKForJava && (i.cfg.Traces.Enabled() || i.cfg.Metrics.Enabled())
}

func (i *SDKInjector) NewExecutable(ie *ebpf.Instrumentable) error {
	if ie.Type == svc.InstrumentableJava {
		ok := i.verifyJVMVersion(ie.FileInfo.Pid)
		if !ok {
			i.log.Info("unsupported Java version for OpenTelemetry Java instrumentation")
			return errors.New("unsupported Java VM version")
		}

		loaded, err := i.jdkAgentAlreadyLoaded(ie.FileInfo.Pid)
		if err != nil {
			return err
		}

		if loaded {
			i.log.Info("OpenTelemetry Java SDK Agent already loaded, not instrumenting.")
			return errors.New("OpenTelemetry Java SDK Agent already loaded")
		}

		i.log.Info("injecting OpenTelemetry SDK instrumentation for Java process", "pid", ie.FileInfo.Pid)

		agentPath, err := i.extractAgent(ie)
		if err != nil {
			i.log.Error("failed to extract java agent", "pid", ie.FileInfo.Pid, "error", err)
			return err
		}

		if err = i.attachJDKAgent(ie.FileInfo.Pid, agentPath, i.cfg); err != nil {
			i.log.Error("couldn't attach OpenTelemetry Java SDK Agent", "pid", ie.FileInfo.Pid, "path", agentPath, "error", err)
			return err
		}

		return nil
	}

	return errors.New("OpenTelemetry SDK instrumentation not possible")
}

func (i *SDKInjector) extractAgent(ie *ebpf.Instrumentable) (string, error) {
	root := ebpfcommon.RootDirectoryForPID(ie.FileInfo.Pid)
	tempDir, err := i.findTempDir(root, ie)
	if err != nil {
		return "", fmt.Errorf("error accessing temp directory: %w", err)
	}

	fullTempDir := filepath.Join(root, tempDir)

	i.log.Info("found injection directory for process", "pid", ie.FileInfo.Pid, "path", fullTempDir)

	const agentFile = "grafana-opentelemetry-java.jar"

	agentPathHost := filepath.Join(fullTempDir, agentFile)

	if err = os.WriteFile(agentPathHost, _agentBytes, 0o644); err != nil {
		return "", fmt.Errorf("error writing file: %w", err)
	}

	agentPathContainer := filepath.Join(tempDir, agentFile)

	return agentPathContainer, nil
}

func otlpOptions(cfg *obi.Config) (map[string]string, error) {
	options := map[string]string{}
	var tracesEndpoint, metricsEndpoint string
	var tracesCommon, metricsCommon bool

	tracesEndpoint, tracesCommon = cfg.Traces.OTLPTracesEndpoint()
	metricsEndpoint, metricsCommon = cfg.Metrics.OTLPMetricsEndpoint()

	if tracesCommon || metricsCommon {
		if tracesEndpoint != metricsEndpoint {
			return nil, errors.New("metrics and traces endpoint definition mismatch, either use OTEL_EXPORTER_OTLP_ENDPOINT for both" +
				" or specify OTEL_EXPORTER_OTLP_TRACES_ENDPOINT and OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
		}
		options["otel.exporter.otlp.endpoint"] = tracesEndpoint
		options["otel.exporter.otlp.protocol"] = string(cfg.Traces.GetProtocol())
		options["otel.metric.export.interval"] = strconv.Itoa(int(cfg.Metrics.GetInterval().Milliseconds()))
		maps.Copy(options, otelcfg.HeadersFromEnv("OTEL_EXPORTER_OTLP_HEADERS"))
	} else {
		if cfg.Traces.Enabled() {
			options["otel.exporter.otlp.traces.endpoint"] = tracesEndpoint
			options["otel.exporter.otlp.traces.protocol"] = string(cfg.Traces.GetProtocol())
			maps.Copy(options, otelcfg.HeadersFromEnv("OTEL_EXPORTER_OTLP_TRACES_HEADERS"))
		} else {
			options["otel.traces.exporter"] = "none"
		}

		if cfg.Metrics.Enabled() {
			options["otel.exporter.otlp.metrics.endpoint"] = metricsEndpoint
			options["otel.exporter.otlp.metrics.protocol"] = string(cfg.Metrics.GetProtocol())
			options["otel.metric.export.interval"] = strconv.Itoa(int(cfg.Metrics.GetInterval().Milliseconds()))
			maps.Copy(options, otelcfg.HeadersFromEnv("OTEL_EXPORTER_OTLP_METRICS_HEADERS"))
		} else {
			options["otel.metrics.exporter"] = "none"
		}
	}

	options["otel.logs.exporter"] = "none"

	return options, nil
}

func flattenOptionsMap(opts map[string]string) string {
	var s []string

	for k, v := range opts {
		if k != "" && v != "" {
			s = append(s, k+"="+v)
		}
	}

	return strings.Join(s, ",")
}

func (i *SDKInjector) attachJDKAgent(pid int32, path string, cfg *obi.Config) error {
	opts, err := otlpOptions(cfg)
	if err != nil {
		i.log.Error("error parsing OTLP options", "err", err)
		return errors.New("error parsing OTLP options")
	}

	// this option needs to appear first in the list
	options := "grafana.otel.debug-agent-startup=true"
	flattenedMap := flattenOptionsMap(opts)

	if len(flattenedMap) > 0 {
		options = options + "," + flattenedMap
		i.log.Info("passing options to the JVM agent", "options", options)
	}

	command := fmt.Sprintf("%s=%s", path, options)

	out, err := jvm.Jattach(int(pid), []string{"load", "instrument", "false", command}, i.log)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return err
	}

	scanner := bufio.NewScanner(out)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "return code: 0") {
			return nil
		} else if strings.Contains(line, "return code:") {
			i.log.Error("error executing command for the JVM", "pid", pid, "message", line)
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Warn("error reading JVM output", "error", err)
	}

	return nil
}

func (i *SDKInjector) jdkAgentAlreadyLoaded(pid int32) (bool, error) {
	out, err := jvm.Jattach(int(pid), []string{"jcmd", "VM.class_hierarchy"}, i.log)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		// We check for com.grafana.GrafanaOpenTelemetryAgent/0x<address>
		if strings.Contains(scanner.Text(), "com.grafana.GrafanaOpenTelemetryAgent/0x") {
			return true, nil
		}
	}

	return false, nil
}

func (i *SDKInjector) verifyJVMVersion(pid int32) bool {
	out, err := jvm.Jattach(int(pid), []string{"jcmd", "VM.version"}, i.log)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "JDK ") {
			return !strings.HasPrefix(line, "JDK 25")
		}
	}
	if err := scanner.Err(); err != nil {
		i.log.Error("error reading from scanner", "error", err)
	}

	return false
}

//go:embed grafana-opentelemetry-java.jar
var _agentBytes []byte
