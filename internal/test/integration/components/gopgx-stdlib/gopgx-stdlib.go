// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	var db *sql.DB
	var err error
	dbInit := false

	http.HandleFunc("/pgxstdlibtest", func(w http.ResponseWriter, r *http.Request) {
		if !dbInit {
			db, err = sql.Open("pgx", "postgres://postgres:postgres@sqlserver:5432/sqltest?sslmode=disable")
			if err != nil {
				log.Printf("Failed to open: %v\n", err)
				w.WriteHeader(500)
				w.Write([]byte("DB open failed"))
				return
			}
			dbInit = true
		}

		// Ping the database to verify the connection
		err = db.Ping()
		if err != nil {
			log.Printf("%v\n", err)
			w.WriteHeader(500)
			return
		}

		// Execute a query using database/sql interface
		rows, err := db.Query("SELECT * from accounting.contacts WHERE id=1")
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

	log.Println("Starting Go pgx stdlib test server on :8080")
	err = http.ListenAndServe(":8080", nil)
	if db != nil {
		db.Close()
	}
}
