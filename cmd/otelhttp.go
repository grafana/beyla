package main

import (
	"fmt"
	"github.com/grafana/http-autoinstrument/pkg/otel"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/context"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/errors"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/process"

	"github.com/caarlos0/env/v6"
	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

type Config struct {
	Endpoint string `env:"OTEL_TRACES_ENDPOINT"`
	Exec     string `env:"EXECUTABLE_NAME"`
}

func main() {
	ho := slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stderr)))

	config := Config{}
	if err := env.Parse(&config); err != nil {
		slog.Error("can't load configuration from environment", err)
		os.Exit(-1)
	}

	pid, err := findProcessID(config.Exec)
	panicOn(err)

	pa := process.NewAnalyzer()
	// TODO: get rid of this
	target, err := pa.Analyze(pid, map[string]interface{}{"net/http.HandlerFunc.ServeHTTP": struct{}{}})
	panicOn(err)

	// TODO: listen for new processes
	exe, err := link.OpenExecutable(fmt.Sprintf("/proc/%d/exe", target.PID))
	panicOn(err)

	ctx := &context.InstrumentorContext{
		Executable:    exe,
		TargetDetails: target,
	}

	httpInstrumentor := nethttp.New()
	panicOn(httpInstrumentor.Load(ctx))

	traceNode := node.AsStart(httpInstrumentor.Run)
	trackerNode := node.AsMiddle(spanner.ConvertToSpan)
	printerNode := node.AsTerminal(func(spans <-chan spanner.HttpRequestSpan) {
		for span := range spans {
			fmt.Printf("connection %s long: %#v\n", span.End.Sub(span.Start), span)
		}
	})
	report, err := otel.Report(config.Endpoint)
	if err != nil {
		panic(err)
	}
	otelNode := node.AsTerminal(report)
	traceNode.SendsTo(trackerNode)
	trackerNode.SendsTo(printerNode)
	trackerNode.SendsTo(otelNode)
	slog.Info("Starting main node")
	traceNode.Start()
	wait := make(chan struct{})
	<-wait
}

func panicOn(err error) {
	if err != nil {
		panic(err)
	}
}

func findProcessID(exePath string) (int, error) {
	// TODO: allow overriding proc for containers
	proc, err := os.Open("/proc")
	if err != nil {
		return 0, err
	}

	for {
		dirs, err := proc.Readdir(15)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		for _, di := range dirs {
			if !di.IsDir() {
				continue
			}

			dname := di.Name()
			if dname[0] < '0' || dname[0] > '9' {
				continue
			}

			pid, err := strconv.Atoi(dname)
			if err != nil {
				return 0, err
			}

			exeName, err := os.Readlink(path.Join("/proc", dname, "exe"))
			if err != nil {
				// Read link may fail if target process runs not as root
				cmdLine, err := ioutil.ReadFile(path.Join("/proc", dname, "cmdline"))
				if err != nil {
					return 0, err
				}

				if strings.Contains(string(cmdLine), exePath) {
					return pid, nil
				}
				// for simplicity, we don't check for full path
				// TODO: support regexpes for better process selection
			} else if strings.Contains(exeName, exePath) {
				return pid, nil
			}
		}
	}

	return 0, errors.ErrProcessNotFound
}
