package main

import (
	"fmt"
	"net"

	"github.com/caarlos0/env/v7"
	"github.com/mariomac/distributed-service-example/worker/pkg/gprc"
	"github.com/mariomac/distributed-service-example/worker/pkg/server"
	"google.golang.org/grpc"
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
