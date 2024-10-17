package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

func main() {
	psqlInit := false
	var db *sql.DB
	var err error

	http.HandleFunc("/psqltest", func(w http.ResponseWriter, r *http.Request) {
		if !psqlInit {
			db, err = sql.Open("postgres", "user=postgres dbname=sqltest sslmode=disable password=postgres host=sqlserver port=5432")
			if err != nil {
				log.Fatal(err)
			}
			psqlInit = true
		}
		// Ping the database to verify the connection
		err = db.Ping()
		if err != nil {
			log.Printf("%v\n", err)
			w.WriteHeader(500)
			return
		}

		// Execute a query
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
			log.Println("no data", err)
			w.WriteHeader(500)
			return
		}

		w.Write([]byte(name + " " + lastNames))
	})

	err = http.ListenAndServe(":8080", nil)
	if db != nil {
		db.Close()
	}
}
