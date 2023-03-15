package gorilla

import (
	"fmt"
	"net/http"

	"github.com/grafana/http-autoinstrument/test/integration/components/testserver/std"

	"github.com/gorilla/mux"
	"golang.org/x/exp/slog"
)

func Setup(port int) {
	log := slog.With("component", "gorilla.Server")
	r := mux.NewRouter()
	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(log))

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, r)
	log.Error("HTTP server has unexpectedly stopped", err)
}
