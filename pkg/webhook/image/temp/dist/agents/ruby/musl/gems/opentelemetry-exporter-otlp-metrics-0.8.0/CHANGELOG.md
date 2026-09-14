# Release History: opentelemetry-exporter-otlp-metrics

### v0.8.0 / 2026-04-07

* ADDED: Min Ruby Version 3.3 (#2070)
* ADDED: Handle HTTP 2XX responses as successful in OTLP exporters (#2044)
* ADDED: Add basic support for metrics exemplar (#1609)
* FIXED: Issue with sending traces to IPv6 endpoints (#1935)

### v0.7.0 / 2026-03-10

* ADDED: Replace cgi with uri for encode and decode (#2028)

### v0.6.1 / 2025-10-17

* FIXED: Increase OTLP Proto version to 1.8.0 to match version in opentelemetry-exporter-otlp

### v0.6.0 / 2025-08-14

- ADDED: Add support for exporting asynchronous instruments

### v0.5.0 / 2025-06-23

- ADDED: Add exponential histogram in otlp metrics exporter

### v0.4.1 / 2025-04-17

- FIXED: Update out-of-date google-protobuf-any

### v0.4.0 / 2025-02-25

- ADDED: Support 3.1 Min Version
- FIXED: Add is_monotonic flag to sum

### v0.3.0 / 2025-01-08

- ADDED: Gauge metrics exporter encoding

### v0.2.1 / 2024-12-04

- FIXED: Handle float value in NumberDataPoint

### v0.2.0 / 2024-11-20

- ADDED: Add basic metrics view
- FIXED: Remove Metrics OTLP exporter `Util#measure_request_duration` and duplicate files
- FIXED: Add mTLS for metrics exporter

### v0.1.0 / 2024-08-27

Initial release.
