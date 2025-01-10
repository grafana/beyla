package gorillamid

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/grafana/beyla/test/integration/components/testserver/std"
)

func Setup(port, stdPort int) {
	log := slog.With("component", "gorilla.Server")
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(log, stdPort))

	middlewares := []Interface{
		StatusConcealer{},
	}

	h := Merge(middlewares...).Wrap(r)

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server with middleware", "address", address)
	err := http.ListenAndServe(address, h)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}
