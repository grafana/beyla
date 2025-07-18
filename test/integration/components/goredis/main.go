package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

func HTTPHandler(log *slog.Logger, echoPort int) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received request", "url", req.RequestURI)

		ctx := context.Background()
		host := "redis:6379"

		if req.RequestURI == "/fail" {
			host = "whatever:6378"
		}

		client := redis.NewClient(&redis.Options{
			Addr:     host,
			Password: "", // no password set
			DB:       0,  // use default DB
		})

		err := client.Set(ctx, "obi", "rocks", 0).Err()
		if err != nil {
			rw.WriteHeader(200) // force a 200 to make oats yaml tests happy
			return
		}

		val, err := client.Get(ctx, "obi").Result()
		if err != nil {
			rw.WriteHeader(200) // force a 200 to make oats yaml tests happy
			return
		}

		status := 200
		for k, v := range req.URL.Query() {
			if len(v) == 0 {
				continue
			}
			switch k {
			case "status":
				if s, err := strconv.Atoi(v[0]); err != nil {
					log.Debug("wrong status value. Ignoring", "error", err)
				} else {
					status = s
				}
			case "delay":
				if d, err := time.ParseDuration(v[0]); err != nil {
					log.Debug("wrong delay value. Ignoring", "error", err)
				} else {
					time.Sleep(d)
				}
			}
		}
		rw.WriteHeader(status)
		rw.Write([]byte(val))
	}
}

func main() {
	log := slog.With("component", "std.Server")
	address := fmt.Sprintf(":%d", 8080)
	log.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, HTTPHandler(log, 8080))
	log.Error("HTTP server has unexpectedly stopped", err)
}
