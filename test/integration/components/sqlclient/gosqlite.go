package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

func main() {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		panic(err)
	}
	// See "Important settings" section.
	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

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
	for i := 1; i < 10; i++ {
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
