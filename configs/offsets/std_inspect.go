package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
)

// This program is used to generate an executable that can be inspected by the go-offsets-tracker tool

func regularGetRequest(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	rt := http.DefaultTransport

	res, err := rt.RoundTrip(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	fmt.Printf("Status: %v\n", res.Status)

	return nil
}

func main() {
	err := regularGetRequest(context.Background(), "http://localhost:8090/rolldice")
	if err != nil {
		os.Exit(1)
	}
	err = http.ListenAndServe(":9090", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// this doesn't need to have any sense!
		writer.WriteHeader(request.ProtoMajor)
	}))
	if err != nil {
		os.Exit(1)
	}
}
