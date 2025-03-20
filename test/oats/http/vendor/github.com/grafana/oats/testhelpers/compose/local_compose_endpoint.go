package compose

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/grafana/oats/observability"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
)

type PortsConfig struct {
	TracesGRPCPort     int
	TracesHTTPPort     int
	TempoHTTPPort      int
	MimirHTTPPort      int
	PrometheusHTTPPort int
	LokiHttpPort       int
}

type ComposeEndpoint struct {
	ComposeFilePath string
	LogOutputPath   string
	Env             []string
	Ports           PortsConfig
}

var _ observability.Endpoint = &ComposeEndpoint{}

var compose *Compose

func NewEndpoint(composeFilePath, logOutputPath string, env []string, ports PortsConfig) *ComposeEndpoint {
	endpoint := &ComposeEndpoint{
		ComposeFilePath: composeFilePath,
		Env:             env,
		LogOutputPath:   logOutputPath,
		Ports:           ports,
	}

	return endpoint
}

func (e *ComposeEndpoint) Start(ctx context.Context) error {
	var err error

	if e.ComposeFilePath == "" {
		return fmt.Errorf("composeFilePath cannot be empty")
	}

	if e.LogOutputPath == "" {
		return fmt.Errorf("logOutputPath cannot be empty")
	}

	compose, err = ComposeSuite(e.ComposeFilePath, e.LogOutputPath)
	if err != nil {
		return err
	}
	err = compose.Up()

	return err
}

func (e *ComposeEndpoint) Stop(ctx context.Context) error {
	return compose.Close()
}

func (e *ComposeEndpoint) Logger() io.WriteCloser {
	return compose.Logger
}

func (e *ComposeEndpoint) TracerProvider(ctx context.Context, r *resource.Resource) (*trace.TracerProvider, error) {
	var exporter *otlptrace.Exporter
	var err error

	if e.Ports.TracesGRPCPort != 0 {
		exporter, err = otlptracegrpc.New(ctx, otlptracegrpc.WithInsecure(), otlptracegrpc.WithEndpoint(fmt.Sprintf("localhost:%d", e.Ports.TracesGRPCPort)))
		if err != nil {
			return nil, err
		}
	} else if e.Ports.TracesHTTPPort != 0 {
		exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithInsecure(), otlptracehttp.WithEndpoint(fmt.Sprintf("localhost:%d/v1/traces", e.Ports.TracesHTTPPort)))
		if err != nil {
			return nil, err
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if exporter == nil {
		return nil, fmt.Errorf("unknown exporter format, specify an OTel trace GRPC or HTTP port")
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(r),
	)

	return traceProvider, nil
}

func (e *ComposeEndpoint) makeGetRequest(url string) ([]byte, error) {
	resp, getErr := http.Get(url)
	if getErr != nil {
		return nil, getErr
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected HTTP status 200, but got: %d", resp.StatusCode)
	}

	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return respBytes, nil
}

func (e *ComposeEndpoint) GetTraceByID(ctx context.Context, id string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	url := fmt.Sprintf("http://localhost:%d/api/traces/%s", e.Ports.TempoHTTPPort, id)
	return e.makeGetRequest(url)
}

func (e *ComposeEndpoint) SearchTempo(ctx context.Context, query string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return e.makeGetRequest(fmt.Sprintf("http://localhost:%d/api/search?q=%s", e.Ports.TempoHTTPPort, url.QueryEscape(query)))
}

func (e *ComposeEndpoint) SearchTags(ctx context.Context, tags map[string]string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var tb strings.Builder

	for tag, val := range tags {
		if tb.Len() != 0 {
			tb.WriteString("&")
		}
		s := tag + "=" + val
		tb.WriteString(url.QueryEscape(s))
	}

	url := fmt.Sprintf("http://localhost:%d/api/search?tags=%s", e.Ports.TempoHTTPPort, tb.String())

	return e.makeGetRequest(url)
}

func (e *ComposeEndpoint) RunPromQL(ctx context.Context, promQL string) ([]byte, error) {
	var u string
	if e.Ports.MimirHTTPPort != 0 {
		u = fmt.Sprintf("http://localhost:%d/prometheus/api/v1/query?query=%s", e.Ports.MimirHTTPPort, url.PathEscape(promQL))
	} else if e.Ports.PrometheusHTTPPort != 0 {
		u = fmt.Sprintf("http://localhost:%d/api/v1/query?query=%s", e.Ports.PrometheusHTTPPort, url.PathEscape(promQL))
	} else {
		return nil, fmt.Errorf("to run PromQL you must configure a MimirHTTPPort or a PrometheusHTTPPort")
	}

	resp, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("querying prometheus: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read response body: %w", err)
	}

	return body, nil
}

func (e *ComposeEndpoint) SearchLoki(query string) ([]byte, error) {
	if e.Ports.LokiHttpPort == 0 {
		return nil, fmt.Errorf("to search Loki you must configure a LokiHttpPort")
	}

	u := fmt.Sprintf("http://localhost:%d/loki/api/v1/query?query=%s", e.Ports.LokiHttpPort, url.PathEscape(query))

	resp, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("querying loki: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read response body: %w", err)
	}

	return body, nil
}
