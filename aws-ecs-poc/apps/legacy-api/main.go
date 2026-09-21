package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/legacy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"service":"legacy-api"}`))
	})

	log.Println("legacy-api listening on :8083 without Beyla instrumentation")
	log.Fatal(http.ListenAndServe(":8083", nil))
}
