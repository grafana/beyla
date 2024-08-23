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

package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.uber.org/zap"
)

// Server is Http server that exposes multiple endpoints.
type Server struct {
	rand *rand.Rand
}

// NewServer creates a server struct after initialing rand.
func NewServer() *Server {
	rd := rand.New(rand.NewSource(time.Now().Unix()))
	return &Server{
		rand: rd,
	}
}

func initOTelProvider() {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:4018" // Default value if the environment variable is not set
	}

	logger.Info("Using OTEL_EXPORTER_OTLP_ENDPOINT", zap.String("endpoint", endpoint))

	murl, err := url.Parse(endpoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	topts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(murl.Host),
		otlptracehttp.WithInsecure(),
		otlptracehttp.WithURLPath(murl.Path + "/v1/traces"),
	}

	texp, err := otlptracehttp.New(context.Background(), topts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	traceProvider := trace.NewTracerProvider(
		trace.WithBatcher(texp),
		trace.WithResource(resource.NewWithAttributes(semconv.SchemaURL, []attribute.KeyValue{
			semconv.ServiceName("dicer"),
			semconv.TelemetrySDKLanguageGo,
			semconv.ServiceNamespace("manual"),
		}...)),
	)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.SetTracerProvider(traceProvider)

	mopts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(murl.Host),
		otlpmetrichttp.WithInsecure(),
		otlpmetrichttp.WithURLPath(murl.Path + "/v1/metrics"),
	}

	mexp, err := otlpmetrichttp.New(context.Background(), mopts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	meterProvider := metric.NewMeterProvider(
		metric.WithResource(resource.NewWithAttributes(semconv.SchemaURL, []attribute.KeyValue{
			semconv.ServiceName("dicer"),
			semconv.TelemetrySDKLanguageGo,
			semconv.ServiceNamespace("manual"),
		}...)),
		metric.WithReader(metric.NewPeriodicReader(mexp,
			// Default is 1m. Set to 3s for demonstrative purposes.
			metric.WithInterval(3*time.Second))),
	)
	otel.SetMeterProvider(meterProvider)
}

func (s *Server) rolldice(w http.ResponseWriter, r *http.Request) {
	n := s.rand.Intn(6) + 1
	logger.Info("rolldice called", zap.Int("dice", n))

	fmt.Fprintf(w, "%v", n)
}

func (s *Server) smoke(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "OK")
}

var logger *zap.Logger

func setupHandlers() {
	s := NewServer()

	otelHandler := otelhttp.NewHandler(http.HandlerFunc(s.rolldice), "Roll")
	http.Handle("/rolldice", otelHandler)

	smokeHandler := otelhttp.NewHandler(http.HandlerFunc(s.smoke), "Smoke")
	http.Handle("/smoke", smokeHandler)
}

func main() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		fmt.Printf("error creating zap logger, error:%v", err)
		return
	}

	initOTelProvider()

	port := fmt.Sprintf(":%d", 8080)
	logger.Info("starting http server", zap.String("port", port))

	setupHandlers()
	if err := http.ListenAndServe(port, nil); err != nil {
		logger.Error("error running server", zap.Error(err))
	}
}
