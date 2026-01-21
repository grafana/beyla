# otelsql

[![ci](https://github.com/XSAM/otelsql/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/XSAM/otelsql/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/XSAM/otelsql/branch/main/graph/badge.svg?token=21S08PK9K0)](https://codecov.io/gh/XSAM/otelsql)
[![Go Report Card](https://goreportcard.com/badge/github.com/XSAM/otelsql)](https://goreportcard.com/report/github.com/XSAM/otelsql)
[![Documentation](https://godoc.org/github.com/XSAM/otelsql?status.svg)](https://pkg.go.dev/mod/github.com/XSAM/otelsql)

It is an OpenTelemetry instrumentation for Golang `database/sql`, a port from https://github.com/open-telemetry/opentelemetry-go-contrib/pull/505.

It instruments traces and metrics.

## Install

```bash
$ go get github.com/XSAM/otelsql
```

## Usage

This project provides four different ways to instrument `database/sql`:

`otelsql.Open`, `otelsql.OpenDB`, `otesql.Register` and `otelsql.WrapDriver`.

And then use `otelsql.RegisterDBStatsMetrics` to instrument `sql.DBStats` with metrics.

```go
db, err := otelsql.Open("mysql", mysqlDSN, otelsql.WithAttributes(
	semconv.DBSystemMySQL,
))
if err != nil {
	panic(err)
}

reg, err := otelsql.RegisterDBStatsMetrics(db, otelsql.WithAttributes(
	semconv.DBSystemMySQL,
))
if err != nil {
	panic(err)
}
defer func() {
	_ = db.Close()
	_ = reg.Unregister()
}()
```

Check [Option](https://pkg.go.dev/github.com/XSAM/otelsql#Option) for more features like adding context propagation to SQL queries when enabling [`WithSQLCommenter`](https://pkg.go.dev/github.com/XSAM/otelsql#WithSQLCommenter).

See [godoc](https://pkg.go.dev/mod/github.com/XSAM/otelsql) for details.

## Blog

[Getting started with otelsql, the OpenTelemetry instrumentation for Go SQL](https://opentelemetry.io/blog/2024/getting-started-with-otelsql), is a blog post that explains how to use otelsql in miutes.

## Examples

This project provides two docker-compose examples to show how to use it.

- [The stdout example](example/stdout) is a simple example to show how to use it with a MySQL database. It prints the trace data to stdout and serves metrics data via prometheus client.
- [The otel-collector example](example/otel-collector) is a more complex example to show how to use it with a MySQL database and an OpenTelemetry Collector. It sends the trace data and metrics data to an OpenTelemetry Collector. Then, it shows data visually on Jaeger and Prometheus servers.

## Semantic Convention Stability Migration

The environment variable `OTEL_SEMCONV_STABILITY_OPT_IN` will be supported for at least six months. After this period, support for legacy metrics and Semantic Conventions `v1.24.0` may be removed in the next release.

Check the [CHANGELOG.md](CHANGELOG.md) for more details.

## Trace Instruments

It creates spans on corresponding [methods](https://pkg.go.dev/github.com/XSAM/otelsql#Method).

Use [`SpanOptions`](https://pkg.go.dev/github.com/XSAM/otelsql#SpanOptions) to adjust creation of spans.

### Trace Semantic Convention Stability

The instrumentation supports different OpenTelemetry semantic convention stability levels, configured through the `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable:

| Setting | Description |
|---------|-------------|
| empty (default) | Only uses `db.statement` attribute. |
| `database/dup` | Uses both `db.statement` and `db.query.text` attributes. |
| `database` | Uses `db.query.text` attribute. |

## Metric Instruments

Two types of metrics are provided depending on the semantic convention stability setting:

### Legacy Metrics (default)
- **db.sql.latency**: The latency of calls in milliseconds
  - Unit: milliseconds
  - Attributes: `method` (method name), `status` (ok, error)

### OpenTelemetry Semantic Convention Metrics
- [**db.client.operation.duration**](https://github.com/open-telemetry/semantic-conventions/blob/v1.32.0/docs/database/database-metrics.md#metric-dbclientoperationduration): Duration of database client operations
  - Unit: seconds
  - Attributes: [`db.operation.name`](https://github.com/open-telemetry/semantic-conventions/blob/v1.32.0/docs/attributes-registry/db.md#db-operation-name) (method name), [`error.type`](https://github.com/open-telemetry/semantic-conventions/blob/v1.32.0/docs/attributes-registry/error.md#error-type) (if error occurs)

### Connection Statistics Metrics (from Go's sql.DBStats)
- **db.sql.connection.max_open**: Maximum number of open connections to the database
- **db.sql.connection.open**: The number of established connections
  - Attributes: `status` (idle, inuse)
- **db.sql.connection.wait**: The total number of connections waited for
- **db.sql.connection.wait_duration**: The total time blocked waiting for a new connection (ms)
- **db.sql.connection.closed_max_idle**: The total number of connections closed due to SetMaxIdleConns
- **db.sql.connection.closed_max_idle_time**: The total number of connections closed due to SetConnMaxIdleTime
- **db.sql.connection.closed_max_lifetime**: The total number of connections closed due to SetConnMaxLifetime

### Metric Semantic Convention Stability

The instrumentation supports different OpenTelemetry semantic convention stability levels, configured through the `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable:

| Setting | Metrics Emitted | Description |
|---------|----------------|-------------|
| empty (default) | `db.sql.latency` only | Only uses legacy metric|
| `database/dup` | Both `db.sql.latency` and `db.client.operation.duration` | Emits both legacy and new OTel metric formats |
| `database` | `db.client.operation.duration` only | Only uses the new OTel semantic convention metric |

Connection statistics metrics (`db.sql.connection.*`) are always emitted regardless of the stability setting.

This allows users to gradually migrate to the new OpenTelemetry semantic conventions while maintaining backward compatibility with existing dashboards and alerts.

## Error Type Attribution

When errors occur during database operations, the `error.type` attribute is automatically populated with the type of the error. This provides more detailed information for debugging and monitoring:

1. **For standard driver errors**: Special handling for common driver errors:
   - `database/sql/driver.ErrBadConn`
   - `database/sql/driver.ErrSkip`
   - `database/sql/driver.ErrRemoveArgument`

2. **For custom errors**: The fully qualified type name is used (e.g., `github.com/your/package.CustomError`).

3. **For built-in errors**: The type name is used (e.g., `*errors.errorString` for errors created with `errors.New()`).

**Note**: The `error.type` attribute is only available when using the new stable OpenTelemetry semantic convention metrics. This requires setting `OTEL_SEMCONV_STABILITY_OPT_IN` to either `database/dup` or `database`. With the default setting (empty), which only uses legacy metrics, the `error.type` attribute will not be populated.

## Compatibility

This project is tested on the following systems.

| OS      | Go Version | Architecture |
| ------- | ---------- | ------------ |
| Ubuntu  | 1.25       | amd64        |
| Ubuntu  | 1.24       | amd64        |
| Ubuntu  | 1.25       | 386          |
| Ubuntu  | 1.24       | 386          |
| MacOS   | 1.25       | amd64        |
| MacOS   | 1.24       | amd64        |
| Windows | 1.25       | amd64        |
| Windows | 1.24       | amd64        |
| Windows | 1.25       | 386          |
| Windows | 1.24       | 386          |

While this project should work for other systems, no compatibility guarantees
are made for those systems currently.

The project follows the [Release Policy](https://golang.org/doc/devel/release#policy) to support major Go releases.

## Why port this?

Based on [this comment](https://github.com/open-telemetry/opentelemetry-go-contrib/pull/505#issuecomment-800452510), OpenTelemetry SIG team like to see broader usage and community consensus on an approach before they commit to the level of support that would be required of a package in contrib. But it is painful for users without a stable version, and they have to use replacement in `go.mod` to use this instrumentation.

Therefore, I host this module independently for convenience and make improvements based on users' feedback.

## Communication

I use GitHub discussions/issues for most communications. Feel free to contact me on CNCF slack.
