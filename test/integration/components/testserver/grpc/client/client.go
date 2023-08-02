/*
 *
 * Based on https://grpc.io/docs/tutorials/basic/go.html
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 */

// Package grpcclient implements a simple gRPC client that demonstrates how to use gRPC-Go libraries
// to perform unary, client streaming, server streaming and full duplex RPCs.
//
// It interacts with the route guide service whose definition can be found in routeguide/route_guide.proto.
package grpcclient

import (
	"context"
	"crypto/tls"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/grafana/ebpf-autoinstrument/test/integration/components/testserver/grpc/routeguide"
)

var logs = slog.With("component", "grpc.Client")

type pingOpts struct {
	ssl        bool
	serverAddr string
}

var defaultPingOpts = pingOpts{serverAddr: "localhost:50051"}

type PingOption func(*pingOpts)

func WithServerAddr(addr string) PingOption {
	return func(opts *pingOpts) {
		opts.serverAddr = addr
	}
}

func WithSSL() PingOption {
	return func(opts *pingOpts) {
		opts.ssl = true
	}
}

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
	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		log.Println(feature)
	}
}

func newClient(po *pingOpts) (pb.RouteGuideClient, io.Closer, error) {
	// Use INFO as default log
	var opts []grpc.DialOption
	if po.ssl {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(po.serverAddr, opts...)
	if err != nil {
		logs.Error("fail to dial", err)
		return nil, conn, err
	}
	return pb.NewRouteGuideClient(conn), conn, nil
}

func Ping(opts ...PingOption) error {
	client, closer, err := newClient(pingConfig(opts))
	defer closer.Close()
	if err != nil {
		return err
	}
	// Looking for a valid feature
	printFeature(client, &pb.Point{Latitude: 409146138, Longitude: -746188906})
	return nil
}

func Debug(processTime time.Duration, forceFail bool, opts ...PingOption) error {
	client, closer, err := newClient(pingConfig(opts))
	defer closer.Close()
	if err != nil {
		return err
	}
	_, err = client.Debug(context.TODO(), &pb.DebugReq{
		ResponseTimeMs: int32(processTime.Milliseconds()),
		Fail:           forceFail,
	})
	return err
}

func pingConfig(opts []PingOption) *pingOpts {
	po := defaultPingOpts
	for _, opt := range opts {
		opt(&po)
	}
	return &po
}
