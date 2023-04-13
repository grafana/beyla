// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nethttp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

const SectionHTTP = "http"
const SectionGRPCStream = "grpc_stream"
const SectionGRPCStatus = "grpc_status"
const SectionRuntimeNewproc1 = "newproc1"
const SectionRuntimeGoexit1 = "goexit1"

type EBPFTracer struct {
	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	Exec string `yaml:"executable_name" env:"EXECUTABLE_NAME"`
	// Port allows selecting the instrumented executable that owns the Port value. If this value is set (and
	// different to zero), the value of the Exec property won't take effect.
	// It's important to emphasize that if your process opens multiple HTTP/GRPC ports, the auto-instrumenter
	// will instrument all the service calls in all the ports, not only the port specified here.
	Port             int      `yaml:"open_port" env:"OPEN_PORT"`
	Functions        []string `yaml:"functions" env:"INSTRUMENT_FUNCTIONS"`
	GRPCHandleStream []string `yaml:"grpc_handle_stream" env:"GRPC_HANDLE_STREAM"`
	GRPCWriteStatus  []string `yaml:"grpc_write_status" env:"GRPC_WRITE_STATUS"`
	RuntimeNewproc1  []string `yaml:"runtime_newproc1" env:"RUNTIME_NEWPROC1"`
	RuntimeGoexit1   []string `yaml:"runtime_goexit1" env:"RUNTIME_GOEXIT1"`
	LogLevel         string   `yaml:"log_level" env:"LOG_LEVEL"`

	Offsets *goexec.Offsets `yaml:"-"`
}

func EBPFTracerProvider(cfg EBPFTracer) node.StartFuncCtx[HTTPRequestTrace] { //nolint:all
	is, err := Instrument(cfg.Offsets, cfg.LogLevel)
	if err != nil {
		slog.Error("can't instantiate eBPF tracer", err)
		os.Exit(-1)
	}
	return is.Run
}

//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 -type http_request_trace bpf ../../../bpf/go_nethttp.c -- -I../../../bpf/headers

// InstrumentedServe allows instrumenting each invocation to the Go standard net/http ServeHTTP
// method handler.
type InstrumentedServe struct {
	bpfObjects   bpfObjects
	uprobes      []link.Link
	eventsReader *ringbuf.Reader
}

// HTTPRequestTrace contains information from an HTTP request as directly received from the
// eBPF layer. This contains low-level C structures so for more comfortable handling from Go,
// HTTPRequestTrace instances are converted to transform.HTTPRequestSpan instances in the
// transform.ConvertToSpan function.
type HTTPRequestTrace bpfHttpRequestTrace

// Instrument the executable passed as path and insert probes in the provided offsets, so the
// returned InstrumentedServe instance will listen and forward traces for each HTTP invocation.
func Instrument(offsets *goexec.Offsets, logLevel string) (*InstrumentedServe, error) {
	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(offsets.FileInfo.ProExeLinkPath)
	if err != nil {
		return nil, fmt.Errorf("opening executable file %q: %w",
			offsets.FileInfo.ProExeLinkPath, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("loading BPF data: %w", err)
	}

	// Set the field offsets and the logLevel for nethttp BPF program
	if err := rewriteConstants(spec, offsets.Field, logLevel); err != nil {
		return nil, err
	}

	h := InstrumentedServe{}
	// Load BPF programs
	if err := spec.LoadAndAssign(&h.bpfObjects, nil); err != nil {
		return nil, instrumentError(err, "loading and assigning BPF objects")
	}

	// Patch the functions to be instrumented
	if err := h.instrumentFunctions(exe, offsets.Funcs); err != nil {
		return nil, err
	}

	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	rd, err := ringbuf.NewReader(h.bpfObjects.Events)
	if err != nil {
		return nil, fmt.Errorf("creating perf reader: %w", err)
	}
	h.eventsReader = rd

	return &h, nil
}

func rewriteConstants(spec *ebpf.CollectionSpec, fields map[string]interface{}, logLevel string) error {
	// Set the log level for nethttp BPF program
	if err := spec.RewriteConstants(map[string]interface{}{"go_http_debug_level": ebpfLogLevel(logLevel)}); err != nil {
		return fmt.Errorf("rewriting BPF log level definition: %w", err)
	}

	if err := spec.RewriteConstants(fields); err != nil {
		return fmt.Errorf("rewriting BPF constants definition: %w", err)
	}

	return nil
}

func (h *InstrumentedServe) instrumentFunctions(exe *link.Executable, funcs map[string][]goexec.FuncOffsets) error {
	for section, funcOffsets := range funcs {
		for _, fn := range funcOffsets {
			switch section {
			case SectionHTTP:
				if err := h.instrumentFunction(fn, exe, h.bpfObjects.UprobeServeHTTP, h.bpfObjects.UprobeServeHttpReturn); err != nil {
					return fmt.Errorf("instrumenting function: %w in section %s", err, section)
				}
			case SectionGRPCStream:
				if err := h.instrumentFunction(fn, exe, h.bpfObjects.UprobeServerHandleStream, h.bpfObjects.UprobeServerHandleStreamReturn); err != nil {
					return fmt.Errorf("instrumenting function: %w in section %s", err, section)
				}
			case SectionGRPCStatus:
				if err := h.instrumentFunction(fn, exe, h.bpfObjects.UprobeTransportWriteStatus, nil); err != nil {
					return fmt.Errorf("instrumenting function: %w in section %s", err, section)
				}
			case SectionRuntimeNewproc1:
				if err := h.instrumentFunction(fn, exe, nil, h.bpfObjects.UprobeProcNewproc1Ret); err != nil {
					return fmt.Errorf("instrumenting function: %w in section %s", err, section)
				}
			case SectionRuntimeGoexit1:
				if err := h.instrumentFunction(fn, exe, h.bpfObjects.UprobeProcGoexit1, nil); err != nil {
					return fmt.Errorf("instrumenting function: %w in section %s", err, section)
				}
			default:
				return fmt.Errorf("unknown section %s", section)
			}
		}
	}

	return nil
}

func (h *InstrumentedServe) instrumentFunction(offsets goexec.FuncOffsets, exe *link.Executable, f *ebpf.Program, fret *ebpf.Program) error {
	// Attach BPF programs as start and return probes
	if f != nil {
		up, err := exe.Uprobe("", f, &link.UprobeOptions{
			Address: offsets.Start,
		})
		if err != nil {
			return instrumentError(err, "setting uprobe")
		}
		h.uprobes = append(h.uprobes, up)
	}

	if fret != nil {
		// Go won't work with Uretprobes because of the way Go manages the stack. We need to set uprobes just before the return
		// values: https://github.com/iovisor/bcc/issues/1320
		for _, ret := range offsets.Returns {
			urp, err := exe.Uprobe("", fret, &link.UprobeOptions{
				Address: ret,
			})
			if err != nil {
				return instrumentError(err, "setting uretprobe")
			}
			h.uprobes = append(h.uprobes, urp)
		}
	}

	return nil
}

// TODO: make use of context to cancel process
func (h *InstrumentedServe) Run(_ context.Context, eventsChan chan<- HTTPRequestTrace) {
	logger := slog.With("name", "net/ebpf-instrumenter")
	var event HTTPRequestTrace
	for {
		logger.Debug("starting to read perf buffer")
		record, err := h.eventsReader.Read()
		logger.Debug("received event")
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Error("error reading from perf reader", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Error("error parsing perf event", err)
			continue
		}

		eventsChan <- event
	}
}

func (h *InstrumentedServe) Close() {
	log := slog.With("name", "net/ebpf-instrumenter")
	log.Info("closing net/http instrumenter")
	if h.eventsReader != nil {
		h.eventsReader.Close()
	}

	for _, urp := range h.uprobes {
		if err := urp.Close(); err != nil {
			log.Warn("closing uprobe", "error", err)
		}
	}

	if err := h.bpfObjects.Close(); err != nil {
		log.Warn("closing BPF program", "error", err)
	}
}

// These levels must match the ones defined in bpf_dbg.h
func ebpfLogLevel(level string) uint8 {
	switch strings.ToLower(level) {
	case "debug":
		return 3
	case "info":
		return 2
	case "warn":
		return 1
	case "error":
		return 0
	default:
		return 1
	}
}

func instrumentError(err error, kind string) error {
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return fmt.Errorf("%s: %w", kind, err)
	}

	fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))

	return fmt.Errorf("%s: %w", kind, ve)
}
