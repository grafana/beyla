package otelsdk

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/jvmtools/jvm"
)

const OTelJDKAgent = "opentelemetry-javaagent-2.14.0.jar"

type SDKInjector struct {
	log *slog.Logger
	cfg *otel.TracesConfig
}

func NewSDKInjector(cfg *otel.TracesConfig) *SDKInjector {
	return &SDKInjector{
		cfg: cfg,
		log: slog.With("component", "otelsdk.Injector"),
	}
}

func (i *SDKInjector) NewExecutable(ie *ebpf.Instrumentable) error {
	if ie.Type == svc.InstrumentableJava {
		info, err := os.Stat(OTelJDKAgent)

		if err != nil || info.IsDir() {
			return fmt.Errorf("invalid OpenTelemetry SDK agent file")
		}

		i.log.Info("injecting OpenTelemetry SDK instrumentation for Java process", "pid", ie.FileInfo.Pid)

		root := ebpfcommon.RootDirectoryForPID(ie.FileInfo.Pid)
		tempDir := filepath.Join(root, "tmp")

		info, err = os.Stat(tempDir)
		if err != nil {
			i.log.Info("error accessing temp directory", "pid", ie.FileInfo.Pid, "error", err)
			return err
		}

		if !info.IsDir() {
			i.log.Info("discovered temp path is not a directory", "pid", ie.FileInfo.Pid, "path", tempDir)
			return fmt.Errorf("not a directory %s", tempDir)
		}

		i.log.Info("found injection directory for process", "pid", ie.FileInfo.Pid, "path", tempDir)
		if err = copyJDKAgent(".", tempDir); err != nil {
			i.log.Error("couldn't copy OpenTelemetry Java SDK Agent", "pid", ie.FileInfo.Pid, "path", tempDir, "error", err)
			return err
		}

		if err = i.attachJDKAgent(ie.FileInfo.Pid, filepath.Join("/tmp", OTelJDKAgent), i.cfg); err != nil {
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

func otlpEndpoint(cfg *otel.TracesConfig) string {
	endpoint := cfg.CommonEndpoint
	if endpoint == "" && cfg.Grafana != nil && cfg.Grafana.CloudZone != "" {
		endpoint = cfg.Grafana.Endpoint()
	}

	return endpoint
}

func (i *SDKInjector) attachJDKAgent(pid int32, path string, cfg *otel.TracesConfig) error {
	endpoint := otlpEndpoint(cfg)
	if endpoint == "" {
		return fmt.Errorf("OTLP endpoint not set")
	}

	command := fmt.Sprintf("%s=otel.exporter.otlp.endpoint=%s", path, endpoint)

	out, err := jvm.Jattach(int(pid), []string{"load", "instrument", "false", command}, i.log)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return err
	}

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		i.log.Info("", "jvm", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		i.log.Error("error reading from scanner", "error", err)
	}

	return nil
}
