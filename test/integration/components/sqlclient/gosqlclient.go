package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "mysecretpassword"
	dbname   = "postgres"
)

func main() {
	psqlconn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	db, err := sql.Open("postgres", psqlconn)
	CheckError(err)
	defer db.Close()

	_, e := db.Exec("DROP TABLE IF EXISTS students")
	CheckError(e)

	_, e = db.Exec("CREATE TABLE students (name	VARCHAR(80), id INT)")
	CheckError(e)

	insertStudent := `INSERT INTO students (name, id) VALUES ($1, $2)`
	_, e = db.Exec(insertStudent, "Bob", 1)
	CheckError(e)
	_, e = db.Exec(insertStudent, "Alice", 2)
	CheckError(e)

	// Do queries for >5 seconds (it may take Beyla that long to find this process)
	for i := 1; i < 6; i++ {
		rows, e := db.Query("SELECT * FROM students")
		CheckError(e)
		defer rows.Close()
		for rows.Next() {
			var name string
			var id int
			e = rows.Scan(&name, &id)
			CheckError(e)
			fmt.Println("name: ", name, " id: ", id)
		}
		time.Sleep(1 * time.Second)
	}
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}
