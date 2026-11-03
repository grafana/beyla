# go-sqllexer

This repository contains a hand written SQL Lexer that tokenizes SQL queries with a focus on obfuscating and normalization. The lexer is written in Go with no external dependencies.
**Note** This is NOT a SQL parser, it only tokenizes SQL queries.

## Features

- :rocket: Fast and lightweight tokenization (not regex based)
- :lock: Obfuscates sensitive data (e.g. numbers, strings, specific literals like dollar quoted strings in Postgres, etc.)
- :book: Even works with truncated queries
- :globe_with_meridians: UTF-8 support
- :wrench: Normalizes obfuscated queries

## Installation

### As a Library

```bash
go get github.com/DataDog/go-sqllexer
```

### As a Command-Line Tool

```bash
# Clone the repository
git clone https://github.com/DataDog/go-sqllexer.git
cd go-sqllexer

# Build the binary
make build

# Or install directly to your PATH
make install
```

## Usage

### Tokenize

```go
import "github.com/DataDog/go-sqllexer"

func main() {
    query := "SELECT * FROM users WHERE id = 1"
    lexer := sqllexer.New(query)
    for {
        token := lexer.Scan()
        if token.Type == EOF {
            break
        }
        fmt.Println(token)
    }
}
```

### Obfuscate

```go
import (
    "fmt"
    "github.com/DataDog/go-sqllexer"
)

func main() {
    query := "SELECT * FROM users WHERE id = 1"
    obfuscator := sqllexer.NewObfuscator()
    obfuscated := obfuscator.Obfuscate(query)
    // "SELECT * FROM users WHERE id = ?"
    fmt.Println(obfuscated)
}
```

### Normalize

```go
import (
    "fmt"
    "github.com/DataDog/go-sqllexer"
)

func main() {
    query := "SELECT * FROM users WHERE id in (?, ?)"
    normalizer := sqllexer.NewNormalizer(
        WithCollectComments(true),
        WithCollectCommands(true),
        WithCollectTables(true),
        WithKeepSQLAlias(false),
    )
    normalized, statementMetadata, err := normalizer.Normalize(query)
    // "SELECT * FROM users WHERE id in (?)"
    fmt.Println(normalized)
}
```

## Command-Line Usage

The `sqllexer` binary provides a command-line interface for all the library functionality:

```bash
# Show help
sqllexer -help

# Obfuscate SQL from stdin
echo "SELECT * FROM users WHERE id = 1" | sqllexer

# Obfuscate SQL from file
sqllexer -input query.sql -output obfuscated.sql

# Normalize SQL for PostgreSQL
sqllexer -mode normalize -dbms postgresql -input query.sql

# Tokenize SQL
sqllexer -mode tokenize -input query.sql

# Obfuscate with custom options
sqllexer -replace-digits=false -keep-json-path=true -input query.sql
```

### Available Modes

- **obfuscate** (default): Replace sensitive data with placeholders
- **normalize**: Normalize SQL queries for consistent formatting
- **tokenize**: Show all tokens in the SQL query

### Database Support

Use the `-dbms` flag to specify the database type:
- `mssql` - Microsoft SQL Server
- `postgresql` - PostgreSQL
- `mysql` - MySQL
- `oracle` - Oracle
- `snowflake` - Snowflake

## Testing

```bash
go test -v ./...
```

## Benchmarks

```bash
go test -bench=. -benchmem ./...
```

## License

[MIT License](LICENSE)
