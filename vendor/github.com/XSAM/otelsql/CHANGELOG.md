# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.41.0] - 2025-12-16

### ⚠️ Notice ⚠️

This release contains breaking changes:

- `RegisterDBStatsMetrics` now returns `(metric.Registration, error)` (previously returned only `error`) so callers can `Unregister()` the callback and avoid memory leaks.
  - If you need to unregister: `reg, err := RegisterDBStatsMetrics(...)` + `defer reg.Unregister()`.
  - If you do not need to unregister: `_, err := RegisterDBStatsMetrics(...)`.
- `WithAttributes` now appends attributes when specified multiple times (previously overwrote existing attributes).
  - If you relied on overwriting: consolidate your attributes into a single `WithAttributes(...)` call.

### Added

- `WithTextMapPropagator` allows customization of the OTel text map propagator used by SQLCommenter. (#540)
  This is an experimental feature and may be changed or removed in a later release.

### Removed

- Drop support for [Go 1.23]. (#533)

### Changed

- Reduce allocations and improve performance when creating spans. (#549)
- Reduce allocations when recording metrics. (#550)
- `RegisterDBStatsMetrics` now returns a `metric.Registration` so callbacks can be unregistered. (#580)
- `WithAttributes` now accumulates attributes across multiple calls instead of overwriting. (#576)
- Upgrade OTel to `v1.39.0`. (#583)

## [0.40.0] - 2025-09-08

This release is the last to support [Go 1.23].
The next release will require at least [Go 1.24].

### Added

- Support testing of [Go 1.25]. (#517)

### Changed

- Upgrade OTel to `v1.38.0/v0.60.0`. (#510)

## [0.39.0] - 2025-06-05

> [!WARNING]
> The new introduced `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable will be supported for at least six months from this release. After this period, support for legacy metrics and Semantic Conventions `v1.24.0` may be removed in the next release.
>
> You can start the migration to the new Semantic Conventions `v1.30.0` by setting the `OTEL_SEMCONV_STABILITY_OPT_IN=database/dup` or `OTEL_SEMCONV_STABILITY_OPT_IN=database` environment variable in your application.
>
> See also the [Semantic conventions for database client metrics](https://opentelemetry.io/docs/specs/semconv/database/database-metrics/).

### Added

- Support to emit query related attributes for the v1.24.0 and v1.30.0 semantic conventions based on the value of the `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable. (#478)

  - `database/dup`: Emit both `db.statement` and `db.query.text` attributes.
  - `database`: Emit `db.query.text` attribute.
  - by default: Emit `db.statement` attribute.

- New `db.client.operation.duration` metric following OpenTelemetry semantic conventions. (#480)
- Support for configuring metrics behavior based on `OTEL_SEMCONV_STABILITY_OPT_IN` setting. (#480)

  - `database/dup`: Emit both legacy latency and new duration `db.client.operation.duration` metrics.
  - `database`: Emit new duration `db.client.operation.duration` metric.
  - by default: Emit only the legacy latency metric.

### Changed

- Upgrade semantic conventions to `semconv/v1.30.0`. (#478)
- Improve memory usage when recording metrics or creating spans. (#497)
- Upgrade OTel to `v1.36.0/v0.58.0`. (#495)

### Fixed

- Data race issues when recording metrics or creating spans. (#497)

## [0.38.0] - 2025-03-26

### Added

- `WithInstrumentErrorAttributesGetter` option to provide additional error-related attributes. (#440)

### Changed

- Upgrade OTel to `v1.35.0/v0.57.0`. (#437)

### Removed

- Drop support for Go `1.22`. (#447)

## [0.37.0] - 2025-02-16

### Added

- `AttributesFromDSN` method to generate `server.address` and `server.port` attributes from a DSN. (#419)
- Go 1.24 to supported versions. (#422)

### Changed

- Upgrade OTel to `v1.34.0/v0.56.0`. (#412)
- Update the comment for the `WithAttributes` option to correctly describe the behavior on measurement creation. (#413)
- Upgrade semantic conventions to `semconv/v1.24.0`. (#418)

## [0.36.0] - 2024-12-18

### Added

- `DisableSkipErrMeasurement` option suppresses `driver.ErrSkip` as an error status in measurements if enabled. (#389)

### Changed

- Upgrade OTel to `v1.33.0/v0.55.0`. (#396)

## [0.35.0] - 2024-10-11

### Changed

- Upgrade OTel to version `v1.31.0/v0.53.0`. (#374)

## [0.34.0] - 2024-09-14

The minimum supported Go version is `1.22`.

### Added

- Go 1.23 to supported versions. (#361)

### Changed

- The `Open` method uses the `dataSourceName` when calling `sql.Open`. (#359)

  This change improves compatibility with certain drivers that perform a verification of the `dataSourceName` before establishing a connection.
- Upgrade OTel to version `v1.30.0/v0.52.0`. (#356)

### Removed

- Support for Go `1.21`. (#356)

## [0.33.0] - 2024-08-27

### Added

- `WithInstrumentAttributesGetter` option provides additional attributes when `latency` histogram is recorded. (#334)

### Changed

- Upgrade OTel to version `v1.29.0/v0.51.0`. (#336)

## [0.32.0] - 2024-07-05

### Changed

- Upgrade OTel to version `v1.28.0/v0.50.0`. (#310)

## [0.31.0] - 2024-05-02

### Changed

- Fallback the check of `driver.NamedValueChecker` to Conn in Stmt. (#243)
  So, the `otelsql` can keep the original check order in `database/sql` for value checkers in the following order,
  stopping at the first found match: `Stmt.NamedValueChecker`, `Conn.NamedValueChecker`.
- Upgrade OTel to version `v1.26.0/v0.48.0`. (#244)

## [0.30.0] - 2024-04-15

### ⚠️ Notice ⚠️

The minimum supported Go version is `1.21`.

### Changed

- Upgrade OTel to version `v1.25.0/v0.47.0`. (#238)

### Removed

- Support for Go `1.20`. (#239)

## [0.29.0] - 2024-02-26

### Changed

- Upgrade OTel to version `v1.24.0/v0.46.0`. (#218)

## [0.28.0] - 2024-02-10

### Added

- Go 1.22 to supported versions. (#210)

### Changed

- Upgrade OTel to version `v1.23.1/v0.45.2`. (#209)

## [0.27.0] - 2023-12-15

### Changed

- ~~Upgrade OTel to version `v1.20.0/v0.43.0`. (#196)~~
- Fixes an issue where `db.Close` did not call `Close` on the underlying connector. (#199)
- Upgrade OTel to version `v1.21.0/v0.44.0`. (#200)

## [0.26.0] - 2023-10-11

### Changed

- Upgrade OTel to version `v1.19.0/v0.42.0`. (#190)

## [0.25.0] - 2023-09-18

### ⚠️ Notice ⚠️

This update contains a breaking change of the type of `SpanNameFormatter`. If you use `SpanNameFormatter` in your code, you need to change the type of `SpanNameFormatter` to function.

The minimum supported Go version is `1.20`.

### Changed

- Upgrade OTel to version `v1.18.0/v0.41.0`. (#184)
- The type of `SpanNameFormatter` has been changed to function for easier use. (#185)

### Removed

- Support for Go `1.19`. (#186)

## [0.24.0] - 2023-09-08

### Added

- `SpanFilter` configuration in `SpanOptions` to filter spans creation. (#174)
- Go 1.21 to supported versions. (#180)

### Changed

- Upgrade OTel to version `v1.17.0/v0.40.0`. (#181)

## [0.23.0] - 2023-05-22

### Changed

- Upgrade OTel to version `1.16.0/0.39.0`. (#170)

## [0.22.0] - 2023-04-28

### ⚠️ Notice ⚠️

The minimum supported Go version is `1.19`.

### Changed

- Upgrade OTel to version `1.15.0/0.38.0`. (#163)

### Removed

- Support for Go `1.18`. Support is now only for Go `1.19` and Go `1.20`. (#164)

## [0.21.0] - 2023-04-16

### ⚠️ Notice ⚠️

This update contains a breaking change of correcting the behavior of returning `driver.ErrSkip` when not permitted by `sql/driver`.

- If your driver uses the old `sql/driver` interfaces, which does not use the `Context` as a parameter, this update may let your driver work with this library.
- If your driver uses the new `sql/driver` interfaces, which use the `Context` as a parameter, this update should not affect your code.

### Changed

- Avoid returning `driver.ErrSkip` when not permitted by `sql/driver`. (#153)
- Upgrade all `semconv` packages to use `v1.18.0`. (#156)

## [0.20.0] - 2023-03-02

### Changed

- Upgrade OTel to version `1.14.0/0.37.0`. (#150)

## [0.19.0] - 2023-02-13

### Added

- Go 1.20 to supported versions. (#146)

### Changed

- Upgrade OTel to version `1.13.0/0.36.0`. (#145)

## [0.18.0] - 2023-02-01

### Changed

- Upgrade OTel to version `1.12.0/0.35.0`. (#139)
- Upgrade all `semconv` packages to use `v1.17.0`. (#141)

## [0.17.1] - 2022-12-13

### Changed

- Upgrade OTel to version `1.11.2/0.34.0`. (#134)

## [0.17.0] - 2022-10-21

### ⚠️ Notice ⚠️

The minimum supported Go version is `1.18`.

### Added

- Go 1.19 to supported versions. (#118)
- `WithAttributesGetter` option provides additional attributes on spans creation. (#125)

### Changed

- Upgrade OTel to version `1.10.0`. (#119)
- Upgrade OTel to version `1.11.0/0.32.3`. (#122)
- Upgrade OTel to version `1.11.1/0.33.0`. (#126)

  This OTel release contains a feature that the `go.opentelemetry.io/otel/exporters/prometheus` exporter now adds a unit suffix to metric names. This can be disabled using the `WithoutUnits()` option added to that package.

### Removed

- Support for Go `1.17`. Support is now only for Go `1.18` and Go `1.19`. (#123)

## [0.16.0] - 2022-08-25

### Added

- `WithSQLCommenter` option to enable context propagation for database by injecting a comment into SQL statements. (#112)

  This is an experimental feature and may be changed or removed in a later release.

### Changed

- Upgrade OTel to version `1.9.0`. (#113)

## [0.15.0] - 2022-07-11

### ⚠️ Notice ⚠️

The minimum supported Go version is `1.17`.

This update contains a breaking change of the removal of `SpanOptions.AllowRoot`.

### Added

- SpanOptions to suppress creation of spans. (#87, #102)

  - `OmitConnResetSession`
  - `OmitConnPrepare`
  - `OmitConnQuery`
  - `OmitRows`
  - `OmitConnectorConnect`

- Function `Raw` to `otConn` to return the underlying driver connection. (#100)

### Changed

- Upgrade OTel to `v1.7.0`. (#91)
- Upgrade OTel to version `1.8.0/0.31.0`. (#105)

### Removed

- Support for Go `1.16`. Support is now only for Go `1.17` and Go `1.18`. (#99)
- `SpanOptions.AllowRoot`. (#101)

## [0.14.1] - 2022-04-07

### Changed

- Upgrade OTel to `v1.6.2`. (#82)

## [0.14.0] - 2022-04-05

### ⚠️ Notice ⚠️

This update is a breaking change of `Open`, `OpenDB`, `Register`, `WrapDriver` and `RegisterDBStatsMetrics` methods.
Code instrumented with these methods will need to be modified.

### Removed

- Remove `dbSystem` parameter from all exported functions. (#80)

## [0.13.0] - 2022-04-04

### Added

- Add Metrics support. (#74)
- Add `Open` and `OpenDB` methods to instrument `database/sql`. (#77)

### Changed

- Upgrade OTel to `v1.6.0/v0.28.0`. (#74)
- Upgrade OTel to `v1.6.1`. (#76)

## [0.12.0] - 2022-03-18

### Added

- Covering connector's connect method with span. (#66)
- Add Go 1.18 to supported versions. (#69)

### Changed

- Upgrade OTel to `v1.5.0`. (#67)

## [0.11.0] - 2022-02-22

### Changed

- Upgrade OTel to `v1.4.1`. (#61)

## [0.10.0] - 2021-12-13

### Changed

- Upgrade OTel to `v1.2.0`. (#50)
- Upgrade OTel to `v1.3.0`. (#54)

## [0.9.0] - 2021-11-05

### Changed

- Upgrade OTel to v1.1.0. (#37)

## [0.8.0] - 2021-10-13

### Changed

- Upgrade OTel to v1.0.1. (#33)

## [0.7.0] - 2021-09-21

### Changed

- Upgrade OTel to v1.0.0. (#31)

## [0.6.0] - 2021-09-06

### Added

- Added RecordError to SpanOption. (#23)
- Added DisableQuery to SpanOption. (#26)

### Changed

- Upgrade OTel to v1.0.0-RC3. (#29)

## [0.5.0] - 2021-08-02

### Changed

- Upgrade OTel to v1.0.0-RC2. (#18)

## [0.4.0] - 2021-06-25

### Changed

- Upgrade to v1.0.0-RC1 of `go.opentelemetry.io/otel`. (#15)

## [0.3.0] - 2021-05-13

### Added

- Add AllowRoot option to prevent backward incompatible. (#13)

### Changed

- Upgrade to v0.20.0 of `go.opentelemetry.io/otel`. (#8)
- otelsql will not create root spans in absence of existing spans by default. (#13)

## [0.2.1] - 2021-03-28

### Fixed

- otelsql does not set the status of span to Error while recording error. (#5)

## [0.2.0] - 2021-03-24

### Changed

- Upgrade to v0.19.0 of `go.opentelemetry.io/otel`. (#3)

## [0.1.0] - 2021-03-23

This is the first release of otelsql.
It contains instrumentation for trace and depends on OTel `v0.18.0`.

### Added

- Instrumentation for trace.
- CI files.
- Example code for a basic usage.
- Apache-2.0 license.

[Go 1.25]: https://go.dev/doc/go1.25
[Go 1.24]: https://go.dev/doc/go1.24
[Go 1.23]: https://go.dev/doc/go1.23

[Unreleased]: https://github.com/XSAM/otelsql/compare/v0.41.0...HEAD
[0.41.0]: https://github.com/XSAM/otelsql/releases/tag/v0.41.0
[0.40.0]: https://github.com/XSAM/otelsql/releases/tag/v0.40.0
[0.39.0]: https://github.com/XSAM/otelsql/releases/tag/v0.39.0
[0.38.0]: https://github.com/XSAM/otelsql/releases/tag/v0.38.0
[0.37.0]: https://github.com/XSAM/otelsql/releases/tag/v0.37.0
[0.36.0]: https://github.com/XSAM/otelsql/releases/tag/v0.36.0
[0.35.0]: https://github.com/XSAM/otelsql/releases/tag/v0.35.0
[0.34.0]: https://github.com/XSAM/otelsql/releases/tag/v0.34.0
[0.33.0]: https://github.com/XSAM/otelsql/releases/tag/v0.33.0
[0.32.0]: https://github.com/XSAM/otelsql/releases/tag/v0.32.0
[0.31.0]: https://github.com/XSAM/otelsql/releases/tag/v0.31.0
[0.30.0]: https://github.com/XSAM/otelsql/releases/tag/v0.30.0
[0.29.0]: https://github.com/XSAM/otelsql/releases/tag/v0.29.0
[0.28.0]: https://github.com/XSAM/otelsql/releases/tag/v0.28.0
[0.27.0]: https://github.com/XSAM/otelsql/releases/tag/v0.27.0
[0.26.0]: https://github.com/XSAM/otelsql/releases/tag/v0.26.0
[0.25.0]: https://github.com/XSAM/otelsql/releases/tag/v0.25.0
[0.24.0]: https://github.com/XSAM/otelsql/releases/tag/v0.24.0
[0.23.0]: https://github.com/XSAM/otelsql/releases/tag/v0.23.0
[0.22.0]: https://github.com/XSAM/otelsql/releases/tag/v0.22.0
[0.21.0]: https://github.com/XSAM/otelsql/releases/tag/v0.21.0
[0.20.0]: https://github.com/XSAM/otelsql/releases/tag/v0.20.0
[0.19.0]: https://github.com/XSAM/otelsql/releases/tag/v0.19.0
[0.18.0]: https://github.com/XSAM/otelsql/releases/tag/v0.18.0
[0.17.1]: https://github.com/XSAM/otelsql/releases/tag/v0.17.1
[0.17.0]: https://github.com/XSAM/otelsql/releases/tag/v0.17.0
[0.16.0]: https://github.com/XSAM/otelsql/releases/tag/v0.16.0
[0.15.0]: https://github.com/XSAM/otelsql/releases/tag/v0.15.0
[0.14.1]: https://github.com/XSAM/otelsql/releases/tag/v0.14.1
[0.14.0]: https://github.com/XSAM/otelsql/releases/tag/v0.14.0
[0.13.0]: https://github.com/XSAM/otelsql/releases/tag/v0.13.0
[0.12.0]: https://github.com/XSAM/otelsql/releases/tag/v0.12.0
[0.11.0]: https://github.com/XSAM/otelsql/releases/tag/v0.11.0
[0.10.0]: https://github.com/XSAM/otelsql/releases/tag/v0.10.0
[0.9.0]: https://github.com/XSAM/otelsql/releases/tag/v0.9.0
[0.8.0]: https://github.com/XSAM/otelsql/releases/tag/v0.8.0
[0.7.0]: https://github.com/XSAM/otelsql/releases/tag/v0.7.0
[0.6.0]: https://github.com/XSAM/otelsql/releases/tag/v0.6.0
[0.5.0]: https://github.com/XSAM/otelsql/releases/tag/v0.5.0
[0.4.0]: https://github.com/XSAM/otelsql/releases/tag/v0.4.0
[0.3.0]: https://github.com/XSAM/otelsql/releases/tag/v0.3.0
[0.2.1]: https://github.com/XSAM/otelsql/releases/tag/v0.2.1
[0.2.0]: https://github.com/XSAM/otelsql/releases/tag/v0.2.0
[0.1.0]: https://github.com/XSAM/otelsql/releases/tag/v0.1.0
