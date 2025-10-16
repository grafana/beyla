package std

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/auto/sdk"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/grafana/beyla/v2/test/integration/components/testserver/arg"
	pb "github.com/grafana/beyla/v2/test/integration/components/testserver/grpc/routeguide"
)

var y2k = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

var tracer = otel.Tracer("trace-example")

func HTTPHandler(log *slog.Logger, echoPort int) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Info("received request", "url", req.RequestURI)

		if req.RequestURI == "/echo" {
			echoAsync(rw, echoPort)
			return
		}

		if req.RequestURI == "/gotracemetoo" {
			echoDist(rw)
			return
		}

		if req.RequestURI == "/echoCall" {
			echoCall(rw)
			return
		}

		if req.RequestURI == "/echoLowPort" {
			echoLowPort(rw)
			return
		}

		if req.RequestURI == "/manual" {
			manual(rw)
			return
		}

		status := arg.DefaultStatus
		for k, v := range req.URL.Query() {
			if len(v) == 0 {
				continue
			}
			switch k {
			case arg.Status:
				if s, err := strconv.Atoi(v[0]); err != nil {
					log.Debug("wrong status value. Ignoring", "error", err)
				} else {
					status = s
				}
			case arg.Delay:
				if d, err := time.ParseDuration(v[0]); err != nil {
					log.Debug("wrong delay value. Ignoring", "error", err)
				} else {
					time.Sleep(d)
				}
			}
		}
		rw.WriteHeader(status)
	}
}

func echoAsync(rw http.ResponseWriter, port int) {
	duration, err := time.ParseDuration("10s")
	if err != nil {
		slog.Error("can't parse duration", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	results := make(chan any)

	go func() {
		echo(rw, port)
		results <- rw
	}()

	for {
		select {
		case <-results:
			return
		case <-ctx.Done():
			slog.Warn("timeout while waiting for test to complete")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func echo(rw http.ResponseWriter, port int) {
	requestURL := "http://localhost:" + strconv.Itoa(port) + "/echoBack?delay=20ms&status=203"

	slog.Debug("calling", "url", requestURL)

	res, err := http.Get(requestURL)
	if err != nil {
		slog.Error("error making http request", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

func inner(id int) {
	ctx := context.Background()
	ts := y2k.Add(10 * time.Microsecond)

	t := tracer

	opts := []trace.SpanStartOption{
		trace.WithAttributes(
			attribute.String("user", "user"+strconv.Itoa(id)),
			attribute.Bool("admin", true),
		),
		trace.WithTimestamp(y2k.Add(500 * time.Microsecond)),
		trace.WithSpanKind(trace.SpanKindServer),
	}

	_, span := t.Start(ctx, fmt.Sprintf("sig_inner %d", id), opts...)
	defer span.End(trace.WithTimestamp(ts.Add(100 * time.Microsecond)))

	if id == 2 {
		span.SetName("changed name")
		span.SetAttributes(
			attribute.String("test", "append"),
		)
	}
}

func manual(rw http.ResponseWriter) {
	slog.Debug("manual spans")

	ctx := context.Background()
	ts := y2k.Add(10 * time.Microsecond)

	provider := sdk.TracerProvider()
	t := provider.Tracer(
		"main",
		trace.WithInstrumentationVersion("v0.0.1"),
		trace.WithSchemaURL("https://some_schema"),
	)

	_, span := t.Start(ctx, "sig", trace.WithTimestamp(ts))
	defer span.End(trace.WithTimestamp(ts.Add(100 * time.Microsecond)))

	inner(1)
	inner(2)

	span.SetStatus(codes.Error, "application error")
	span.RecordError(
		errors.New("some unknown error"),
		trace.WithTimestamp(y2k.Add(2*time.Second)),
		trace.WithStackTrace(true),
		trace.WithAttributes(attribute.Int("impact", 11)),
	)

	rw.WriteHeader(http.StatusOK)
}

var (
	addrLowPort = net.TCPAddr{Port: 7000}
	transport   = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			LocalAddr: &addrLowPort,
		}).DialContext,
	}
)
var httpClient = &http.Client{Transport: transport}

func echoLowPort(rw http.ResponseWriter) {
	requestURL := os.Getenv("TARGET_URL")

	slog.Debug("calling", "url", requestURL)

	res, err := httpClient.Get(requestURL)
	if err != nil {
		slog.Error("error making http request", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

func echoDist(rw http.ResponseWriter) {
	requestURL := "http://testserver:8088/jsonrpc"

	slog.Debug("calling", "url", requestURL)

	res, err := http.Post(requestURL, "application/json", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"Arith.Traceme","params":[{"A":1,"B":2}],"id":1}`)))
	if err != nil {
		slog.Error("error making http request", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

func echoCall(rw http.ResponseWriter) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient("localhost:5051", opts...)
	if err != nil {
		slog.Error("fail to dial", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)

	point := &pb.Point{Latitude: 409146138, Longitude: -746188906}

	slog.Debug("Getting feature for point", "lat", point.Latitude, "long", point.Longitude)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.GetFeature(ctx, point)
	if err != nil {
		slog.Error("client.GetFeature failed", "error", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func Setup(port int) {
	log := slog.With("component", "std.Server")
	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, HTTPHandler(log, port))
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}

func SetupTLS(port int) {
	log := slog.With("component", "std.Server")
	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTPS server", "address", address)
	err := http.ListenAndServeTLS(address, "x509/server_test_cert.pem", "x509/server_test_key.pem", HTTPHandler(log, port))
	log.Error("HTTPS server has unexpectedly stopped", "error", err)
}
