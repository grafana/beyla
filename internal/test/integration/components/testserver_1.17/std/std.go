package std

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/grafana/beyla/v2/testserver_1.17/arg"
	pb "github.com/grafana/beyla/v2/testserver_1.17/grpc/routeguide"
)

func HTTPHandler(echoPort int) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		fmt.Printf("received request with url %s\n", req.RequestURI)

		if req.RequestURI == "/echo" {
			echoAsync(rw, echoPort)
			return
		}

		if req.RequestURI == "/echoCall" {
			echoCall(rw)
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
					fmt.Printf("wrong status value. Ignoring error %w\n", err)
				} else {
					status = s
				}
			case arg.Delay:
				if d, err := time.ParseDuration(v[0]); err != nil {
					fmt.Printf("wrong delay value. Ignoring error %w\n", err)
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
		fmt.Printf("can't parse duration %w\n", err)
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
			fmt.Printf("timeout while waiting for test to complete\n")
			rw.WriteHeader(500)
			return
		}
	}
}

func echo(rw http.ResponseWriter, port int) {
	requestURL := "http://localhost:" + strconv.Itoa(port) + "/echoBack?delay=20ms&status=203"

	fmt.Printf("calling url %s\n", requestURL)

	res, err := http.Get(requestURL)
	if err != nil {
		fmt.Printf("error making http request %w\n", err)
		rw.WriteHeader(500)
		return
	}

	defer res.Body.Close()
	rw.WriteHeader(res.StatusCode)
}

func echoCall(rw http.ResponseWriter) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	conn, err := grpc.Dial("localhost:5051", opts...)
	if err != nil {
		fmt.Printf("fail to dial %w\n", err)
		rw.WriteHeader(500)
		return
	}
	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)

	point := &pb.Point{Latitude: 409146138, Longitude: -746188906}

	fmt.Printf("Getting feature for point lat %v long %v\n", point.Latitude, point.Longitude)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.GetFeature(ctx, point)
	if err != nil {
		fmt.Printf("client.GetFeature failed %w\n", err)
		rw.WriteHeader(500)
		return
	}
	rw.WriteHeader(204)
}

func Setup(port int) {
	address := fmt.Sprintf(":%d", port)
	fmt.Printf("starting HTTP server at address %s\n", address)
	err := http.ListenAndServe(address, HTTPHandler(port))
	fmt.Printf("HTTP server has unexpectedly stopped %w\n", err)
}
