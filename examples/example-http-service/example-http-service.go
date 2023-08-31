package main

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"time"
)

// Simple example HTTP service for trying out Beyla.
// 20% of calls will fail with HTTP status 500.

func handleRequest(rw http.ResponseWriter, _ *http.Request) {
	time.Sleep(time.Duration(rand.Float64()*400.0) * time.Millisecond)
	if rand.Int31n(100) < 80 {
		rw.WriteHeader(200)
		if _, err := io.WriteString(rw, "Hello from the example HTTP service.\n"); err != nil {
			log.Fatal(err)
		}
	} else {
		rw.WriteHeader(500)
		if _, err := io.WriteString(rw, "Simulating an error response with HTTP status 500.\n"); err != nil {
			log.Fatal(err)
		}
	}
}

func main() {
	fmt.Println("Listening on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(handleRequest)))
}
