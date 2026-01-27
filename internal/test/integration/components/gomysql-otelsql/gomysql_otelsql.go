package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/XSAM/otelsql"
	_ "github.com/go-sql-driver/mysql"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func main() {
	mysqlInit := false
	var db *sql.DB
	var err error

	http.HandleFunc("/mysqltest", func(w http.ResponseWriter, r *http.Request) {
		if !mysqlInit {
			// Use otelsql.Open instead of sql.Open - this wraps the MySQL driver
			db, err = otelsql.Open("mysql", "root:mysql@tcp(mysqlserver:3306)/sqltest",
				otelsql.WithAttributes(
					semconv.DBSystemMySQL,
					semconv.ServerAddress("mysqlserver"),
					semconv.ServerPort(3306),
				),
			)
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

		// Use QueryContext to test the instrumentation
		rows, err := db.QueryContext(r.Context(), "SELECT * from students WHERE id=1")
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

	http.HandleFunc("/exectest", func(w http.ResponseWriter, r *http.Request) {
		if !mysqlInit {
			db, err = otelsql.Open("mysql", "root:mysql@tcp(mysqlserver:3306)/sqltest",
				otelsql.WithAttributes(
					semconv.DBSystemMySQL,
					semconv.ServerAddress("mysqlserver"),
					semconv.ServerPort(3306),
				),
			)
			if err != nil {
				log.Fatal(err)
			}
			mysqlInit = true
		}

		// Use ExecContext to test the instrumentation
		_, err := db.ExecContext(r.Context(), "UPDATE students SET name='Jane Doe' WHERE id=1")
		if err != nil {
			log.Printf("%v\n", err)
			w.WriteHeader(500)
			return
		}
		fmt.Fprintf(w, "Updated student")
	})

	log.Println("Starting Go MySQL test server with otelsql on :8080")
	http.ListenAndServe(":8080", nil)
}
