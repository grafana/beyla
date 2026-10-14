package main

import (
	"log"
	"net/http"
	"strconv"
	"time"
)

// Simple web service that just returns Ok to any path.
// For testing, it accepts the following arguments in order to change the
// response:
const (
	argForceReturnCode = "force_ret"
	argForceDelay      = "force_delay"
)

func handleRequest(rw http.ResponseWriter, req *http.Request) {
	log.Println("received request", req.RequestURI)
	// handle forced delay
	if d, err := strconv.Atoi(req.URL.Query().Get(argForceDelay)); err == nil {
		time.Sleep(time.Duration(d) * time.Millisecond)
	}

	// handle forced response code
	retCode := http.StatusOK
	if r, err := strconv.Atoi(req.URL.Query().Get(argForceReturnCode)); err == nil {
		retCode = r
	}

	rw.WriteHeader(retCode)
}

func main() {
	log.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(handleRequest)))
}
