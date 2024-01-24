package main

import (
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

func main() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %v, http: %v\n", r.URL.Path, r.TLS == nil)
	})

	server := &http.Server{
		Addr:    "0.0.0.0:7373",
		Handler: handler,
	}
	http2.ConfigureServer(server, nil)

	fmt.Printf("Listening [0.0.0.0:7373]...\n")
	checkErr(server.ListenAndServeTLS("cert.pem", "key.pem"), "while listening")
}
