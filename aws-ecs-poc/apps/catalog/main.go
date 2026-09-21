package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	checkoutURL := os.Getenv("CHECKOUT_URL")
	if checkoutURL == "" {
		log.Fatal("CHECKOUT_URL is required")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	http.HandleFunc("/catalog", func(w http.ResponseWriter, _ *http.Request) {
		response, err := client.Get(checkoutURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()

		body, err := io.ReadAll(response.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		if response.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("checkout returned %s: %s", response.Status, body), http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprintf(w, "catalog -> %s", body)
	})

	log.Println("catalog listening on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}
