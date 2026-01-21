package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var tls = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")

func main() {
	flag.Parse()

	grpcServ := grpc.NewServer()
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", home)

	mySvc := &MyGrpcService{}
	grpc_health_v1.RegisterHealthServer(grpcServ, mySvc)

	// Create a channel to receive OS signals
	sigChan := make(chan os.Signal, 1)
	// Notify the channel on interrupt signals (Ctrl+C)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		os.Exit(0)
	}()

	reflection.Register(grpcServ)

	mixedHandler := newHTTPandGRPCMux(httpMux, grpcServ)
	http2Server := &http2.Server{}
	http1Server := &http.Server{Handler: h2c.NewHandler(mixedHandler, http2Server)}

	var lis net.Listener
	var err error
	if *tls {
		lis, err = net.Listen("tcp", ":8383")
		if err != nil {
			panic(err)
		}
		fmt.Printf("Listening and serving TLS on port 8383...\n")
		err = http1Server.ServeTLS(lis, "x509/server_test_cert.pem", "x509/server_test_key.pem")
	} else {
		lis, err = net.Listen("tcp", ":8080")
		if err != nil {
			panic(err)
		}
		fmt.Printf("Listening and serving TLS on port 8080...\n")
		err = http1Server.Serve(lis)
	}
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Println("server closed")
	} else if err != nil {
		panic(err)
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello from http handler!\n")
}

type MyGrpcService struct {
	grpc_health_v1.UnimplementedHealthServer
}

func (m *MyGrpcService) Check(_ context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}

func (m *MyGrpcService) Watch(_ *grpc_health_v1.HealthCheckRequest, _ grpc_health_v1.Health_WatchServer) error {
	panic("not implemented")
}

func newHTTPandGRPCMux(httpHand http.Handler, grpcHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("content-type"), "application/grpc") {
			grpcHandler.ServeHTTP(w, r)
			return
		}
		httpHand.ServeHTTP(w, r)
	})
}
