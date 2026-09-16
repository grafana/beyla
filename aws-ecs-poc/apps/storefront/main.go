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

	client := &http.Client{Timeout: 2 * time.Second}
	go generateTraffic(client, checkoutURL)

	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		body, err := callCheckout(client, checkoutURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprintf(w, "storefront -> %s\n", body)
	})

	log.Println("storefront listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func generateTraffic(client *http.Client, checkoutURL string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		body, err := callCheckout(client, checkoutURL)
		if err != nil {
			log.Printf("checkout request failed: %v", err)
			continue
		}
		log.Printf("checkout response: %s", body)
	}
}

func callCheckout(client *http.Client, checkoutURL string) (string, error) {
	response, err := client.Get(checkoutURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checkout returned %s: %s", response.Status, body)
	}
	return string(body), nil
}
