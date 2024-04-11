package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/net/http2"
)

func checkErr(err error, msg string) {
	if err == nil {
		return
	}
	fmt.Printf("ERROR: %s: %s\n", msg, err)
	os.Exit(1)
}

func roundTripExample() {
	req, err := http.NewRequestWithContext(context.Background(), "GET", os.Getenv("TARGET_URL")+"/pingrt", nil)
	checkErr(err, "during new request")

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	resp, err := tr.RoundTrip(req)
	checkErr(err, "during roundtrip")

	if err == nil {
		fmt.Printf("RoundTrip Proto: %d\n", resp.ProtoMajor)
	}
}

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %v, http: %v\n", r.URL.Path, r.TLS == nil)
	})

	server := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: handler,
	}
	err := http2.ConfigureServer(server, nil)
	checkErr(err, "configuring server")

	roundTripExample()
	fmt.Printf("Listening [0.0.0.0:8080]...\n")
	checkErr(server.ListenAndServeTLS("cert.pem", "key.pem"), "while listening")
}
