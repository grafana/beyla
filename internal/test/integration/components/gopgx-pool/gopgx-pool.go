// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	var pool *pgxpool.Pool
	var err error
	poolInit := false

	http.HandleFunc("/pgxpooltest", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if !poolInit {
			pool, err = pgxpool.New(ctx, "postgres://postgres:postgres@sqlserver:5432/sqltest?sslmode=disable")
			if err != nil {
				log.Printf("Failed to create pool: %v\n", err)
				w.WriteHeader(500)
				w.Write([]byte("Pool creation failed"))
				return
			}
			poolInit = true
		}

		// Execute a query using pgxpool
		rows, err := pool.Query(ctx, "SELECT * from accounting.contacts WHERE id=1")
		if err != nil {
			log.Printf("%v\n", err)
			w.WriteHeader(500)
			return
		}
		defer rows.Close()

		var name, lastNames, address string
		var id int

		if rows.Next() {
			err = rows.Scan(&id, &name, &lastNames, &address)
			if err != nil {
				log.Printf("%v\n", err)
				w.WriteHeader(500)
				return
			}
			fmt.Println("name: ", name, " id: ", id)
		} else {
			log.Println("no data", rows.Err())
			w.WriteHeader(500)
			return
		}

		w.Write([]byte(name + " " + lastNames))
	})

	log.Println("Starting Go pgx pool test server on :8080")
	err = http.ListenAndServe(":8080", nil)
	if pool != nil {
		pool.Close()
	}
}
