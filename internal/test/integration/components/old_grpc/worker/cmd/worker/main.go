package main

import (
	"fmt"
	"net"

	"github.com/caarlos0/env/v7"
	"google.golang.org/grpc"

	"github.com/grafana/beyla/v2/internal/test/integration/components/old_grpc/worker/internal/gprc"
	"github.com/grafana/beyla/v2/internal/test/integration/components/old_grpc/worker/internal/server"
)

type Config struct {
	Port int `env:"PORT" envDefault:"5000"`
}

func main() {
	cfg := Config{}
	panicOnErr(env.Parse(&cfg))

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	panicOnErr(err)

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)
	gprc.RegisterMultiplierServer(grpcServer, &server.MultiplyServer{})
	panicOnErr(grpcServer.Serve(lis))
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
