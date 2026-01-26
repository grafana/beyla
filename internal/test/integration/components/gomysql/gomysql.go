package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	mysqlInit := false
	var db *sql.DB
	var err error

	http.HandleFunc("/mysqltest", func(w http.ResponseWriter, r *http.Request) {
		if !mysqlInit {
			db, err = sql.Open("mysql", "root:mysql@tcp(mysqlserver:3306)/sqltest")
			if err != nil {
				log.Fatal(err)
			}
			mysqlInit = true
		}
		err = db.Ping()
		if err != nil {
			log.Printf("%v\n", err)
			w.WriteHeader(500)
			return
		}

		rows, err := db.Query("SELECT * from students WHERE id=1")
		if err != nil {
			log.Printf("%v\n", err)
			w.WriteHeader(500)
			return
		}
		defer rows.Close()

		var name string
		var id int
		for rows.Next() {
			err = rows.Scan(&name, &id)
			if err != nil {
				log.Printf("%v\n", err)
				w.WriteHeader(500)
				return
			}
		}
		fmt.Fprintf(w, "Student: %s, ID: %d", name, id)
	})

	http.HandleFunc("/mysqlerror", func(w http.ResponseWriter, r *http.Request) {
		if !mysqlInit {
			db, err = sql.Open("mysql", "root:mysql@tcp(mysqlserver:3306)/sqltest")
			if err != nil {
				log.Printf("Failed to connect: %v\n", err)
				w.WriteHeader(200)
				w.Write([]byte("DB connection failed (expected)"))
				return
			}
			mysqlInit = true
		}

		// Execute broken SQL - this should return an error
		rows, err := db.Query("SELECT * FROM nonexistent_table WHERE id=1")
		if err != nil {
			log.Printf("Expected error from broken SQL: %v\n", err)
			w.WriteHeader(200) // Return 200 for OATS framework, actual SQL error is in trace
			w.Write([]byte("SQL error (expected)"))
			return
		}
		defer rows.Close()

		w.Write([]byte("unexpected success"))
	})

	log.Println("Starting Go MySQL test server on :8080")
	http.ListenAndServe(":8080", nil)
}
