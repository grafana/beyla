---
title: Stability Guarantees
menuTitle: Stability Guarantees
description: This section covers the major version stability guarantees for Beyla.
weight: 7
keywords:
  - Beyla
  - Stability
  - Compatibility
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/stability/
---

# Stability Guarantees

Beyla promises configuration and exposition format stability within a major version, and strives to avoid breaking changes for key features.
Some features, which are of cosmetic nature, experimental or still under development, are not covered by this. We can only guarantee stability
for Linux kernel, or eBPF features of the Linux kernel, versions released at the time the Beyla major version was released.

## Things considered stable for version 1.x:

- The configuration file format and all of the existing configuration options.
  New configuration options might be added in minor releases, but we'll never
  remove or rename an existing option within a major release.
- The configuration environment variable names and their format.
- The externally perceived behaviour of the configuration options, regardless if
  the option was supplied via the configuration file or the environment variables.
- The OpenTelemetry and Prometheus exposition formats. If we need to add support
  for newer exposition formats, we'll provide an opt-in way to enable those. The
  only exception to this rule is the `telemetry.sdk.language` resource attribute
  (see "detection of new programming languages" below).
- The type of telemetry data we produce, e.g. metrics and traces.

## Things considered unstable for 1.x:

- Any features marked as experimental in the documentation are subject to
  change in a minor release.
- The log output of Beyla, or which messages will appear at
  which logging levels.
- The number or types of eBPF probes that we'll install
  in each Beyla version.
- The detection of new programming languages. We may add support for detecting
  new programming languages, so the reported telemetry SDK language field may
  change between minors for previously undetected languages.
