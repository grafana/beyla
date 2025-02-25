package otelsdk

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/jvmtools/jvm"
)

const OTelJDKAgent = "opentelemetry-javaagent.jar"

type SDKInjector struct {
	log *slog.Logger
	cfg *beyla.Config
}

func NewSDKInjector(cfg *beyla.Config) *SDKInjector {
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

	return "", fmt.Errorf("couldn't find suitable temp directory for injection")
}

func (i *SDKInjector) Enabled() bool {
	return i.cfg.EBPF.UseOTelSDKForJava && (i.cfg.Traces.Enabled() || i.cfg.Metrics.Enabled())
}

func (i *SDKInjector) NewExecutable(ie *ebpf.Instrumentable) error {
	if ie.Type == svc.InstrumentableJava {
		info, err := os.Stat(OTelJDKAgent)

		if err != nil || info.IsDir() {
			return fmt.Errorf("invalid OpenTelemetry SDK agent file")
		}

		loaded, err := i.jdkAgentAlreadyLoaded(ie.FileInfo.Pid)
		if err != nil {
			return err
		}

		if loaded {
			i.log.Info("OpenTelemetry Java SDK Agent already loaded, not instrumenting.")
			return fmt.Errorf("OpenTelemetry Java SDK Agent already loaded")
		}

		i.log.Info("injecting OpenTelemetry SDK instrumentation for Java process", "pid", ie.FileInfo.Pid)

		root := ebpfcommon.RootDirectoryForPID(ie.FileInfo.Pid)
		tempDir, err := i.findTempDir(root, ie)
		fullTempDir := filepath.Join(root, tempDir)

		if err != nil {
			i.log.Error("error accessing temp directory", "pid", ie.FileInfo.Pid, "error", err)
			return err
		}

		i.log.Info("found injection directory for process", "pid", ie.FileInfo.Pid, "path", fullTempDir)
		if err = copyJDKAgent(".", fullTempDir); err != nil {
			i.log.Error("couldn't copy OpenTelemetry Java SDK Agent", "pid", ie.FileInfo.Pid, "path", fullTempDir, "error", err)
			return err
		}

		if err = i.attachJDKAgent(ie.FileInfo.Pid, filepath.Join(tempDir, OTelJDKAgent), i.cfg); err != nil {
			i.log.Error("couldn't attach OpenTelemetry Java SDK Agent", "pid", ie.FileInfo.Pid, "path", tempDir, "error", err)
			return err
		}

		return nil
	}

	return fmt.Errorf("OpenTelemetry SDK instrumentation not possible")
}

func copyJDKAgent(srcDir, dstDir string) error {
	// Open the source file
	sourceFile, err := os.Open(filepath.Join(srcDir, OTelJDKAgent))
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	// Create the destination file
	destFile, err := os.Create(filepath.Join(dstDir, OTelJDKAgent))
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// Copy the contents from source to destination
	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy contents: %w", err)
	}

	// Flush the contents to disk
	err = destFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to flush contents to disk: %w", err)
	}

	return nil
}

func expandHeadersWithAuth(options map[string]string, key string, value string) {
	if existing, ok := options[key]; ok {
		options[key] = existing + ",Authorization=" + value
	} else {
		options[key] = "Authorization=" + value
	}
}

func otlpOptions(cfg *beyla.Config) (map[string]string, error) {
	options := map[string]string{}
	var tracesEndpoint, metricsEndpoint string
	var tracesCommon, metricsCommon bool

	tracesEndpoint, tracesCommon = cfg.Traces.OTLPTracesEndpoint()
	metricsEndpoint, metricsCommon = cfg.Metrics.OTLPMetricsEndpoint()

	if tracesCommon || metricsCommon {
		if tracesEndpoint != metricsEndpoint {
			return nil, fmt.Errorf("metrics and traces endpoint definition mismatch, either use OTEL_EXPORTER_OTLP_ENDPOINT for both" +
				" or specify OTEL_EXPORTER_OTLP_TRACES_ENDPOINT and OTEL_EXPORTER_OTLP_METRICS_ENDPOINT.")
		}
		options["otel.exporter.otlp.endpoint"] = tracesEndpoint
		options["otel.exporter.otlp.protocol"] = string(cfg.Traces.GetProtocol())
		maps.Copy(options, otel.HeadersFromEnv("OTEL_EXPORTER_OTLP_HEADERS"))
		if cfg.Traces.Grafana.HasAuth() {
			expandHeadersWithAuth(options, "OTEL_EXPORTER_OTLP_HEADERS", cfg.Traces.Grafana.AuthHeader())
		}
	} else {
		if cfg.Traces.Enabled() {
			options["otel.exporter.otlp.traces.endpoint"] = tracesEndpoint
			options["otel.exporter.otlp.traces.protocol"] = string(cfg.Traces.GetProtocol())
			maps.Copy(options, otel.HeadersFromEnv("OTEL_EXPORTER_OTLP_TRACES_HEADERS"))
			if cfg.Traces.Grafana.HasAuth() {
				expandHeadersWithAuth(options, "OTEL_EXPORTER_OTLP_TRACES_HEADERS", cfg.Traces.Grafana.AuthHeader())
			}
		}
		if cfg.Metrics.Enabled() {
			options["otel.exporter.otlp.metrics.endpoint"] = metricsEndpoint
			options["otel.exporter.otlp.metrics.protocol"] = string(cfg.Metrics.GetProtocol())
			maps.Copy(options, otel.HeadersFromEnv("OTEL_EXPORTER_OTLP_METRICS_HEADERS"))
			if cfg.Metrics.Grafana.HasAuth() {
				expandHeadersWithAuth(options, "OTEL_EXPORTER_OTLP_METRICS_HEADERS", cfg.Metrics.Grafana.AuthHeader())
			}
			if !cfg.Traces.Enabled() {
				options["otel.propagators"] = "none"
			}
		}
	}

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

func (i *SDKInjector) attachJDKAgent(pid int32, path string, cfg *beyla.Config) error {
	opts, err := otlpOptions(cfg)
	if err != nil {
		i.log.Error("error parsing OTLP options", "err", err)
		return fmt.Errorf("error parsing OTLP options")
	}

	options := flattenOptionsMap(opts)

	if len(options) > 0 {
		i.log.Info("passing options to the JVM agent", "options", options)
	}

	// TODO: this needs to also check if grpc is used instead of HTTP
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
		// We check for io.opentelemetry.javaagent.OpenTelemetryAgent/0x<address>
		if strings.Contains(scanner.Text(), "io.opentelemetry.javaagent.OpenTelemetryAgent/0x") {
			return true, nil
		}
	}

	return false, nil
}
