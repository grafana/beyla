// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/jackc/pgx/v5"
)

func main() {
	pgxInit := false
	var conn *pgx.Conn
	var err error

	http.HandleFunc("/pgxquery", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if !pgxInit {
			conn, err = pgx.Connect(ctx, "postgres://postgres:postgres@sqlserver:5432/sqltest?sslmode=disable")
			if err != nil {
				log.Printf("Failed to connect: %v\n", err)
				w.WriteHeader(500)
				w.Write([]byte("DB connection failed"))
				return
			}
			pgxInit = true
		}

		// Ping the database to verify the connection
		err = conn.Ping(ctx)
		if err != nil {
			log.Printf("%v\n", err)
			w.WriteHeader(500)
			return
		}

		// Execute a query
		rows, err := conn.Query(ctx, "SELECT * from accounting.contacts WHERE id=1")
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

	http.HandleFunc("/pgxupdate", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if !pgxInit {
			conn, err = pgx.Connect(ctx, "postgres://postgres:postgres@sqlserver:5432/sqltest?sslmode=disable")
			if err != nil {
				log.Printf("Failed to connect: %v\n", err)
				w.WriteHeader(500)
				w.Write([]byte("DB connection failed"))
				return
			}
			pgxInit = true
		}

		// Execute an update
		cmdTag, err := conn.Exec(ctx, "UPDATE accounting.contacts SET address='Updated Address' WHERE id=1")
		if err != nil {
			log.Printf("Exec error: %v\n", err)
			w.WriteHeader(500)
			w.Write([]byte("Exec failed"))
			return
		}

		w.Write([]byte(fmt.Sprintf("Updated %d rows", cmdTag.RowsAffected())))
	})

	// Endpoint with broken SQL
	http.HandleFunc("/pgxerror", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if !pgxInit {
			conn, err = pgx.Connect(ctx, "postgres://postgres:postgres@sqlserver:5432/sqltest?sslmode=disable")
			if err != nil {
				log.Printf("Failed to connect: %v\n", err)
				w.WriteHeader(500)
				w.Write([]byte("DB connection failed"))
				return
			}
			pgxInit = true
		}

		// Execute broken SQL - this should return an error
		rows, err := conn.Query(ctx, "SELECT * FROM nonexistent_table WHERE id=1")
		if err != nil {
			log.Printf("Expected error from broken SQL: %v\n", err)
			// Return 200 so OATS framework continues
			w.WriteHeader(200)
			w.Write([]byte("SQL error (expected)"))
			return
		}
		defer rows.Close()

		w.Write([]byte("unexpected success"))
	})

	log.Println("Starting Go pgx test server on :8080")
	err = http.ListenAndServe(":8080", nil)
	if conn != nil {
		conn.Close(context.Background())
	}
}
