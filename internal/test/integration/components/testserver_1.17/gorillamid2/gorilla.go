package gorillamid2

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/grafana/beyla/v2/testserver_1.17/std"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("I'm authenticating this request\n")
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("I'm logging this request\n")
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

func Setup(port, stdPort int) {
	r := mux.NewRouter()
	var handler http.Handler
	handler = std.HTTPHandler(stdPort)
	handler = AuthMiddleware(handler)
	handler = LoggingMiddleware(handler)
	r.PathPrefix("/").Handler(handler)

	address := fmt.Sprintf(":%d", port)
	fmt.Printf("starting HTTP server with middleware at address %s\n", address)
	err := http.ListenAndServe(address, handler)
	fmt.Printf("HTTP server has unexpectedly stopped %w\n", err)
}
