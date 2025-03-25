package gorillamid

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/grafana/beyla/v2/testserver_1.17/std"
)

func Setup(port, stdPort int) {
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(stdPort))

	middlewares := []Interface{
		StatusConcealer{},
	}

	h := Merge(middlewares...).Wrap(r)

	address := fmt.Sprintf(":%d", port)
	fmt.Printf("starting HTTP server with middleware at address %s\n", address)
	err := http.ListenAndServe(address, h)
	fmt.Printf("HTTP server has unexpectedly stopped %w\n", err)
}
