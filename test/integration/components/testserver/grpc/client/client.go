/*
 *
 * Based on https://grpc.io/docs/tutorials/basic/go.html
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 */

// Package main implements a simple gRPC client that demonstrates how to use gRPC-Go libraries
// to perform unary, client streaming, server streaming and full duplex RPCs.
//
// It interacts with the route guide service whose definition can be found in routeguide/route_guide.proto.
package grpcclient

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"os"
	"time"

	pb "github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/grpc/routeguide"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var logs = slog.With("component", "grpc.Client")

var (
	ssl        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	serverAddr = flag.String("addr", "localhost:50051", "The server address in the format of host:port")
)

// printFeature gets the feature for the given point.
func printFeature(client pb.RouteGuideClient, point *pb.Point) {
	slog.Debug("Getting feature for point", "lat", point.Latitude, "long", point.Longitude)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	feature, err := client.GetFeature(ctx, point)
	if err != nil {
		logs.Error("client.GetFeature failed", err)
		os.Exit(-1)
	}
	if slog.Default().Enabled(slog.LevelDebug) {
		log.Println(feature)
	}
}

func Ping() error {
	// Use INFO as default log
	flag.Parse()
	var opts []grpc.DialOption
	if *ssl {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		logs.Error("fail to dial", err)
		return err
	}
	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)

	// Looking for a valid feature
	printFeature(client, &pb.Point{Latitude: 409146138, Longitude: -746188906})
	return nil
}
