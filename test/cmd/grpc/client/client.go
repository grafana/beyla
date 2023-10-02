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
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/rand"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/grafana/beyla/test/cmd/grpc/routeguide"
)

var (
	ssl        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	serverAddr = flag.String("addr", "localhost:50051", "The server address in the format of host:port")
	ping       = flag.Bool("ping", false, "Simple ping instead of full chatter")
	wrapper    = flag.Bool("wrapper", false, "Simple ping with wrapper call to pingserver")
)

// printFeature gets the feature for the given point.
func printFeature(client pb.RouteGuideClient, point *pb.Point, counter int) {
	slog.Debug("Getting feature for point", "lat", point.Latitude, "long", point.Longitude)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var traceID [16]byte
	var spanID [8]byte
	binary.BigEndian.PutUint64(traceID[:8], uint64(counter))
	binary.BigEndian.PutUint64(spanID[:], uint64(counter))

	// Generate a traceparent that we easily recognize
	tp := fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID[:]), hex.EncodeToString(spanID[:]))

	// Anything linked to this variable will transmit request headers.
	md := metadata.New(map[string]string{"traceparent": tp})
	ctx = metadata.NewOutgoingContext(ctx, md)

	feature, err := client.GetFeature(ctx, point)
	if err != nil {
		slog.Error("client.GetFeature failed", err)
		os.Exit(-1)
	}
	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		log.Println(feature)
	}
}

// printFeature gets the feature for the given point.
func printFeatureWrapper(client pb.RouteGuideClient, point *pb.Point) {
	slog.Debug("Getting feature for point", "lat", point.Latitude, "long", point.Longitude)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	feature, err := client.GetFeatureWrapper(ctx, point)
	if err != nil {
		slog.Error("client.GetFeature failed", err)
		os.Exit(-1)
	}
	if slog.Default().Enabled(context.TODO(), slog.LevelDebug) {
		log.Println(feature)
	}
}

// printFeatures lists all the features within the given bounding Rectangle.
func printFeatures(client pb.RouteGuideClient, rect *pb.Rectangle) {
	slog.Info("Looking for features within", "rect", rect)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.ListFeatures(ctx, rect)
	if err != nil {
		slog.Error("client.ListFeatures failed", err)
		os.Exit(-1)
	}
	for {
		feature, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			slog.Error("client.ListFeatures failed", err)
			os.Exit(-1)
		}
		slog.Info("Feature: ", "name", feature.GetName(),
			"lat", feature.GetLocation().GetLatitude(), "long", feature.GetLocation().GetLongitude())
	}
}

// runRecordRoute sends a sequence of points to server and expects to get a RouteSummary from server.
func runRecordRoute(client pb.RouteGuideClient) {
	// Create a random number of random points
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	pointCount := int(r.Int31n(100)) + 2 // Traverse at least two points
	var points []*pb.Point
	for i := 0; i < pointCount; i++ {
		points = append(points, randomPoint(r))
	}
	slog.Info("Traversing points: ", "number", len(points))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.RecordRoute(ctx)
	if err != nil {
		slog.Error("client.RecordRoute failed", err)
		os.Exit(-1)
	}
	for _, point := range points {
		if err := stream.Send(point); err != nil {
			slog.Error("client.RecordRoute: stream.Send failed", err, "point", point)
			os.Exit(-1)
		}
	}
	reply, err := stream.CloseAndRecv()
	if err != nil {
		slog.Error("client.RecordRoute failed", err)
		os.Exit(-1)
	}
	slog.Info("Route summary", "reply", reply)
}

// runRouteChat receives a sequence of route notes, while sending notes for various locations.
func runRouteChat(client pb.RouteGuideClient) {
	notes := []*pb.RouteNote{
		{Location: &pb.Point{Latitude: 0, Longitude: 1}, Message: "First message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 2}, Message: "Second message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 3}, Message: "Third message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 1}, Message: "Fourth message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 2}, Message: "Fifth message"},
		{Location: &pb.Point{Latitude: 0, Longitude: 3}, Message: "Sixth message"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := client.RouteChat(ctx)
	if err != nil {
		slog.Error("client.RouteChat failed", err)
		os.Exit(-1)
	}
	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				// read done.
				close(waitc)
				return
			}
			if err != nil {
				slog.Error("client.RouteChat failed", err)
				os.Exit(-1)
			}
			slog.Info("Got", "message", in.Message, "lat", in.Location.Latitude, "long", in.Location.Longitude)
		}
	}()
	for _, note := range notes {
		if err := stream.Send(note); err != nil {
			slog.Error("client.RouteChat:", err, "stream.Send", note)
			os.Exit(-1)
		}
	}
	err = stream.CloseSend()
	if err != nil {
		slog.Error("client.CloseSend", err)
		os.Exit(-1)
	}
	<-waitc
}

func randomPoint(r *rand.Rand) *pb.Point {
	lat := (r.Int31n(180) - 90) * 1e7
	long := (r.Int31n(360) - 180) * 1e7
	return &pb.Point{Latitude: lat, Longitude: long}
}

func main() {
	// Use INFO as default log
	lvl := slog.LevelInfo

	lvlEnv, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL is set, let's default to the desired level
	if ok {
		err := lvl.UnmarshalText([]byte(lvlEnv))
		if err != nil {
			slog.Error("unknown log level specified, choises are [DEBUG, INFO, WARN, ERROR]", errors.New(lvlEnv))
			os.Exit(-1)
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	})))

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
		slog.Error("fail to dial", err)
		os.Exit(-1)
	}
	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)

	if *wrapper {
		printFeatureWrapper(client, &pb.Point{Latitude: 409146138, Longitude: -746188906})
		return
	}

	counter := 1

	// Looking for a valid feature
	printFeature(client, &pb.Point{Latitude: 409146138, Longitude: -746188906}, counter)

	if !*ping {
		counter++
		// Feature missing.
		printFeature(client, &pb.Point{Latitude: 0, Longitude: 0}, counter)

		// Looking for features between 40, -75 and 42, -73.
		printFeatures(client, &pb.Rectangle{
			Lo: &pb.Point{Latitude: 400000000, Longitude: -750000000},
			Hi: &pb.Point{Latitude: 420000000, Longitude: -730000000},
		})

		// RecordRoute
		runRecordRoute(client)

		// RouteChat
		runRouteChat(client)
	} else {
		for {
			time.Sleep(5 * time.Second)
			counter++
			printFeature(client, &pb.Point{Latitude: 409146138, Longitude: -746188906}, counter)
		}
	}
}
