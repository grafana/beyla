# Release History: opentelemetry-metrics-sdk

### v0.13.1 / 2026-04-15

* FIXED: Move the metrics-sdk requires to support "require 'opentelemetry/sdk/metrics'" (#1956)

### v0.13.0 / 2026-04-07

* ADDED: Min Ruby Version 3.3 (#2070)
* ADDED: Add basic support for metrics exemplar (#1609)

### v0.12.0 / 2026-02-11

* BREAKING CHANGE: Fix the issue of mixed scale with multiple attributes

* FIXED: Fix the issue of mixed scale with multiple attributes

### v0.11.2 / 2025-12-02

* FIXED: Add merge logic for exponential histogram when the temporality cumulative

### v0.11.1 / 2025-11-04

* FIXED: Do not log error when there are no metrics to export

### v0.11.0 / 2025-10-28

* ADDED: Add logging about export status to Metrics SDK

### v0.10.1 / 2025-10-21

* FIXED: Update callback timeout mechanism to use Thread

### v0.10.0 / 2025-10-14

* ADDED: Use common method for returning timestamp in nanoseconds

### v0.9.1 / 2025-09-16

* FIXED: Use mapping scale outside of rescale logic

### v0.9.0 / 2025-08-19

* ADDED: Add `LOWMEMORY` option to `OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE`

### v0.8.0 / 2025-08-14

- BREAKING CHANGE: Update default aggregation temporality for counter, histogram, and up down counter to cumulative

- ADDED: Support asynchronous instruments: ObservableGauge, ObservableCounter and ObservableUpDownCounter
- FIXED: Validate scale range on exponential histograms and raise exception if out of bounds
- FIXED: Update max instrument name length from 63 to 255 characters and allow `/` in instrument names
- FIXED: Validate scale range and raise exception if out of bounds for exponential histograms

### v0.7.3 / 2025-07-09

- FIXED: Stop exporting metrics with empty data points

### v0.7.2 / 2025-07-03

- FIXED: Coerce aggregation temporality to be a symbol for exponential histograms

### v0.7.1 / 2025-05-28

- FIXED: Recover periodic metric readers after forking

### v0.7.0 / 2025-05-13

- ADDED: Add basic exponential histogram

### v0.6.1 / 2025-04-09

- FIXED: Use condition signal to replace sleep and remove timeout.timeout…

### v0.6.0 / 2025-02-25

- ADDED: Support 3.1 Min Version
- FIXED: Add is_monotonic flag to sum

### v0.5.0 / 2025-01-08

- ADDED: Add synchronous gauge

### v0.4.1 / 2024-12-04

- FIXED: Handle float value in NumberDataPoint

### v0.4.0 / 2024-11-20

- ADDED: Update metrics configuration patch

### v0.3.0 / 2024-10-22

- ADDED: Add basic metrics view
- FIXED: Coerce aggregation_temporality to symbol
- FIXED: Add warning if invalid meter name given

### v0.2.0 / 2024-08-27

- ADDED: Add basic periodic exporting metric_reader

### v0.1.0 / 2024-07-31

Initial release.
