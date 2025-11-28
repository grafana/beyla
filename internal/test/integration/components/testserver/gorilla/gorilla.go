package gorilla

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/grafana/beyla/v2/internal/test/integration/components/testserver/std"
)

func Setup(port, stdPort int) {
	log := slog.With("component", "gorilla.Server")
	r := mux.NewRouter()

	api := r.PathPrefix("/rolldice").Subrouter()

	api.HandleFunc("/{id}", func(w http.ResponseWriter, r *http.Request) {
		// Extract the id variable from the URL
		vars := mux.Vars(r)
		diceID := vars["id"]

		log.Info("received rolldice", "id", diceID)

		// Set response header and encode JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		err := json.NewEncoder(w).Encode(diceID)
		if err != nil {
			log.Error("error encoding json", "error", err)
		}
	}).Methods("GET")

	r.PathPrefix("/").HandlerFunc(std.HTTPHandler(log, stdPort))

	address := fmt.Sprintf(":%d", port)
	log.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, r)
	log.Error("HTTP server has unexpectedly stopped", "error", err)
}
