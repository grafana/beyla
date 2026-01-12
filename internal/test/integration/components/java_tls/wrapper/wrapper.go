// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

var httpClient *http.Client

func initHTTPClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 90 * time.Second, // Large keep-alive timeout
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10, // Maximum idle connections per host
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func regularGetRequest(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("Error %v\n", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

func main() {
	initHTTPClient()

	http.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		err := regularGetRequest(r.Context(), "https://testserver:8443/greeting")

		if err != nil {
			fmt.Printf("Error %v\n", err)
		}

		w.Write([]byte("OK"))
	})

	fmt.Printf("Listening on port 8080\n")
	http.ListenAndServe(":8080", nil)
}
