package std

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/grafana/beyla/test/integration/components/testserver/arg"
	pb "github.com/grafana/beyla/test/integration/components/testserver/grpc/routeguide"
)

func HTTPHandler(log *slog.Logger, echoPort int) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received request", "url", req.RequestURI)

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
		rw.WriteHeader(500)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	results := make(chan interface{})

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
			rw.WriteHeader(500)
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
		rw.WriteHeader(500)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

var addrLowPort = net.TCPAddr{Port: 7000}
var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		LocalAddr: &addrLowPort,
	}).DialContext,
}
var httpClient = &http.Client{Transport: transport}

func echoLowPort(rw http.ResponseWriter) {

	requestURL := os.Getenv("TARGET_URL")

	slog.Debug("calling", "url", requestURL)

	res, err := httpClient.Get(requestURL)
	if err != nil {
		slog.Error("error making http request", "error", err)
		rw.WriteHeader(500)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

func echoDist(rw http.ResponseWriter) {
	requestURL := "http://pytestserver:8083/tracemetoo"

	slog.Debug("calling", "url", requestURL)

	res, err := http.Get(requestURL)
	if err != nil {
		slog.Error("error making http request", "error", err)
		rw.WriteHeader(500)
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
		rw.WriteHeader(500)
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
		rw.WriteHeader(500)
		return
	}
	rw.WriteHeader(204)
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
