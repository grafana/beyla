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
	catalogURL := os.Getenv("CATALOG_URL")
	if catalogURL == "" {
		log.Fatal("CATALOG_URL is required")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	go generateTraffic(client, catalogURL)

	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		body, err := callCatalog(client, catalogURL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_, _ = fmt.Fprintf(w, "storefront -> %s\n", body)
	})

	log.Println("storefront listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func generateTraffic(client *http.Client, catalogURL string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		body, err := callCatalog(client, catalogURL)
		if err != nil {
			log.Printf("catalog request failed: %v", err)
			continue
		}
		log.Printf("catalog response: %s", body)
	}
}

func callCatalog(client *http.Client, catalogURL string) (string, error) {
	response, err := client.Get(catalogURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("catalog returned %s: %s", response.Status, body)
	}
	return string(body), nil
}
