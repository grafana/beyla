package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/grafana/beyla/v2/internal/test/cmd/grpc/routeguide"
)

const (
	delayArg    = "delay"
	envPort     = "SERVER_PORT"
	defaultPort = 5000
)

func serve(rw http.ResponseWriter, req *http.Request) {
	slog.Debug("connection established", "remoteAddr", req.RemoteAddr)

	switch req.URL.Path {
	case "/ping":
		pingHandler(rw, req)
	case "/gping":
		gpingHandler(rw, req)
	case "/aping":
		pingAsync(rw, req)
	default:
		slog.Info("not found", "url", req.URL)
		rw.WriteHeader(http.StatusNotFound)
		return
	}
}

func pingAsync(rw http.ResponseWriter, req *http.Request) {
	duration, err := time.ParseDuration("10s")

	if err != nil {
		slog.Error("can't parse duration", "error", err)
		os.Exit(-1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	results := make(chan interface{})

	go func() {
		pingHandler(rw, req)
		results <- rw
	}()

	for {
		select {
		case <-results:
			return
		case <-ctx.Done():
			slog.Warn("timeout while waiting for test to complete")
			return
		}
	}
}

func pingHandler(rw http.ResponseWriter, req *http.Request) {
	var delay = 0 * time.Second

	if req.URL.Query().Has(delayArg) {
		delay, _ = time.ParseDuration(req.URL.Query().Get(delayArg))
	}

	requestURL := "http://localhost:8080/ping"
	if delay > 0 {
		requestURL += fmt.Sprintf("?delay=%s", delay.String())
	}

	slog.Debug("calling", "url", requestURL)

	res, err := http.Get(requestURL)
	if err != nil {
		fmt.Printf("error making http request: %s\n", err)
		os.Exit(1)
	}

	defer res.Body.Close()

	rw.WriteHeader(res.StatusCode)
	if res.StatusCode == http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			slog.Error("reading response", "error", err, "url", req.URL)
		}
		b, err := rw.Write(bodyBytes)
		if err != nil {
			slog.Error("writing response", "error", err, "url", req.URL)
			return
		}
		slog.Debug(fmt.Sprintf("%T", rw))
		slog.Debug("written response", "url", req.URL, slog.Int("bytes", b))
	}
}

func gpingHandler(rw http.ResponseWriter, _ *http.Request) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.NewClient("localhost:5051", opts...)
	if err != nil {
		slog.Error("fail to dial", "error", err)
		os.Exit(-1)
	}
	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)

	point := &pb.Point{Latitude: 409146138, Longitude: -746188906}

	slog.Debug("Getting feature for point", "lat", point.Latitude, "long", point.Longitude)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	feature, err := client.GetFeature(ctx, point)
	if err != nil {
		slog.Error("client.GetFeature failed", "error", err)
		// nolint:gocritic
		os.Exit(-1)
	}
	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		log.Println(feature)
	}
	rw.WriteHeader(204)
}

func main() {
	// Use INFO as default log
	lvl := slog.LevelInfo

	lvlEnv, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL is set, let's default to the desired level
	if ok {
		err := lvl.UnmarshalText([]byte(lvlEnv))
		if err != nil {
			slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", "error", errors.New(lvlEnv))
			os.Exit(-1)
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	})))

	port := defaultPort
	if ps, ok := os.LookupEnv(envPort); ok {
		var err error
		if port, err = strconv.Atoi(ps); err != nil {
			slog.Error("parsing port", "error", err, "value", ps)
			os.Exit(-1)
		}
	}
	slog.Info("listening and serving", "port", port, "process_id", os.Getpid())
	panic(http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(serve)))
}
