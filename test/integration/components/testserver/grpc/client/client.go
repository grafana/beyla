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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/grafana/beyla/test/integration/components/testserver/grpc/routeguide"
)

var logs = slog.With("component", "grpc.Client")
var counter int64

type pingOpts struct {
	ssl        bool
	serverAddr string
}

var defaultPingOpts = pingOpts{serverAddr: "localhost:5051"}

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
func printFeature(ctx context.Context, client pb.RouteGuideClient, point *pb.Point) error {
	slog.Debug("Getting feature for point", "lat", point.Latitude, "long", point.Longitude)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	feature, err := client.GetFeature(ctx, point)
	if err != nil {
		logs.Error("client.GetFeature failed", "error", err)
		// nolint:gocritic
		return err
	}
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		log.Println(feature)
	}
	return nil
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

	conn, err := grpc.NewClient(po.serverAddr, opts...)
	if err != nil {
		logs.Error("fail to dial", "error", err)
		return nil, conn, err
	}
	return pb.NewRouteGuideClient(conn), conn, nil
}

func Ping(opts ...PingOption) error {
	return PingCtx(context.Background(), opts...)
}

func PingCtx(ctx context.Context, opts ...PingOption) error {
	client, closer, err := newClient(pingConfig(opts))
	defer closer.Close()
	if err != nil {
		return err
	}
	// Looking for a valid feature
	err = printFeature(ctx, client, &pb.Point{Latitude: 409146138, Longitude: -746188906})
	return err
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

// printFeatures lists all the features within the given bounding Rectangle.
func printFeatures(client pb.RouteGuideClient, rect *pb.Rectangle) {
	slog.Debug("Looking for features within", "rect", rect)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cnt := atomic.AddInt64(&counter, 1)

	var traceID [16]byte
	var spanID [8]byte
	binary.BigEndian.PutUint64(traceID[:8], uint64(cnt))
	binary.BigEndian.PutUint64(spanID[:], uint64(cnt))
	// Generate a traceparent that we easily recognize
	tp := fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID[:]), hex.EncodeToString(spanID[:]))

	// Anything linked to this variable will transmit request headers.
	md := metadata.New(map[string]string{"traceparent": tp})
	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := client.ListFeatures(ctx, rect)
	if err != nil {
		slog.Error("client.ListFeatures failed", "error", err)
		// nolint:gocritic
		os.Exit(-1)
	}
	for {
		feature, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			slog.Error("client.ListFeatures failed", "error", err)
			os.Exit(-1)
		}
		slog.Debug("Feature: ", "name", feature.GetName(),
			"lat", feature.GetLocation().GetLatitude(), "long", feature.GetLocation().GetLongitude())
	}
}

func List(opts ...PingOption) error {
	client, closer, err := newClient(pingConfig(opts))
	defer closer.Close()
	if err != nil {
		return err
	}
	// Looking for a valid feature
	printFeatures(client, &pb.Rectangle{
		Lo: &pb.Point{Latitude: 400000000, Longitude: -750000000},
		Hi: &pb.Point{Latitude: 420000000, Longitude: -730000000},
	})
	return nil
}
