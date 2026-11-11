<img src="docs/sources/assets/logo.png" height=226 alt="Grafana Beyla logo">

# Grafana Beyla

Open source zero-code automatic instrumentation with eBPF and OpenTelemetry.

[![status badge](https://github.com/grafana/beyla/actions/workflows/publish_gar_release.yml/badge.svg)](https://github.com/grafana/beyla/actions/workflows/publish_gar_release.yml)
[![License](https://img.shields.io/github/license/grafana/beyla)](https://github.com/grafana/beyla/blob/main/LICENSE)

## Important Update for current and future Beyla contributors

Beyla has been [donated](https://github.com/open-telemetry/community/issues/2406) to the CNCF OpenTelemetry Project, under the project name 
[OpenTelemetry eBPF Instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation) or **OBI** for short. We are in
the process of vendoring most of the code that exists in the Beyla source repository from upstream. If you are working on a PR, unless it's
related to documentation, please make the PR to the [upstream repository](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation). All Beyla current maintainers work full time on the upstream repository.

We expect that the process of migrating all development to the upstream repository to finish shortly. Some parts of the upstream codebase will
likely be imported as a git submodule.

## Introduction

Beyla is a vendor agnostic, eBPF-based, OpenTelemetry/Prometheus application auto-instrumentation tool, which lets you easily get started with Application Observability. 
eBPF is used to automatically inspect application executables and the OS networking layer, allowing us to capture essential application observability events
for HTTP/S and gRPC services. From these captured eBPF events, we produce OpenTelemetry web transaction trace spans and Rate-Errors-Duration (RED) metrics. 
As with most eBPF tools, all data capture and instrumentation occurs without any modifications to your application code or configuration.

## Community

To engage with the Beyla community and to chat with us on our community Slack channel, 
please invite yourself to the Grafana Slack, visit https://slack.grafana.com/ and join the #beyla channel.

We also run a monthly Beyla community call, on the second Wednesday of the month at **4pm UTC**. You can
find all of the details about our community call on the [Grafana Community Calendar](https://calendar.google.com/calendar/u/0/embed?src=grafana.com_n57lluqpn4h4edroeje6199o00@group.calendar.google.com).

## Getting Started

To try out Beyla, you need to run a network service for Beyla to instrument.
Beyla supports a wide range of programming languages (Go, Java, .NET, NodeJS, Python, Ruby, Rust, etc.),
so if you already have an example service you can use it.
If you don't have an example, you can download and run `example-http-service.go` from the `examples/` directory:

```
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/example-http-service/example-http-service.go
go run ./example-http-service.go
```

Next, generate some traffic. The following command will trigger a GET request to http://localhost:8080 every two seconds.

```
watch curl -s http://localhost:8080
```

Now that we have an example running, we are ready to download and run Beyla.

First, download and unpack the latest release from the [GitHub releases page](https://github.com/grafana/beyla/releases).
The release should contain the `./beyla` executable.

Beyla supports multiple ways to find the service to be instrumented (by network port, executable name, process ID),
and multiple exposition formats (Prometheus, OpenTelemetry metrics, Distributed Traces for Go, Single Span traces for 
other languages).

For getting started, we'll tell Beyla to instrument the service running on port 8080 (our example service) and expose metrics in Prometheus format on port 9400.

```
export BEYLA_PROMETHEUS_PORT=9400
export BEYLA_OPEN_PORT=8080
sudo -E ./beyla
```

Now, you should see metrics on [http://localhost:9400/metrics](http://localhost:9400/metrics).

See [Documentation](https://grafana.com/docs/beyla/) and the [tutorials](https://grafana.com/docs/beyla/latest/tutorial/) for more info.

## Requirements

- Linux with Kernel 5.8 or higher with [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html)
  enabled, or Linux distributions running RedHat Enterprise Linux 4.18 kernels build 348 and above as they have the required kernel backports. These include CentOS, AlmaLinux, and Oracle Linux. BTF became enabled by default on most Linux distributions with kernel 5.14 or higher.
  You can check if your kernel has BTF enabled by verifying if `/sys/kernel/btf/vmlinux` exists on your system.
  If you need to recompile your kernel to enable BTF, the configuration option `CONFIG_DEBUG_INFO_BTF=y` must be
  set.
- eBPF enabled on the host.
- For instrumenting Go programs, they must have been compiled with at least Go 1.17. We currently
  support Go applications built with a major **Go version no earlier than 3 versions** behind the current
  stable major release.
- Some level of elevated permissions to execute the instrumenter:
    - On host systems, running Beyla requires `sudo`.
    - For Kubernetes we have detailed configuration example on how to run with minimum
      required capabilities in the [examples/k8s/unprivileged.yaml](./examples/k8s/unprivileged.yaml) file.
    - For docker compose, you need to setup Beyla as `privileged` container or grant the `SYS_ADMIN` capability.

| Available Instrumentations                    | Supported  |
|-----------------------------------------------|------------|
| HTTP/HTTPS/HTTP2                              | ✅         |
| gRPC                                          | ✅         |
| SQL                                           | ✅         |
| Redis                                         | ✅         |
| Kafka                                         | ✅         |
| MongoDB                                       | ✅         |

The Go instrumentation is limited to certain specific libraries.

| Available Go Instrumentations                       | Supported  |
|-----------------------------------------------------|------------|
| Standard Go `net/http`                              | ✅         |
| [Gorilla Mux](https://github.com/gorilla/mux)       | ✅         |
| [Gin](https://gin-gonic.com/)                       | ✅         |
| [gRPC-Go](https://github.com/grpc/grpc-go)          | ✅         |
| [Go x/net/http2](https://golang.org/x/net/http2)    | ✅         |
| [Go-Redis v9](github.com/redis/go-redis)            | ✅         |
| [Sarama Kafka](github.com/IBM/sarama)               | ✅         |
| [kafka-Go](https://github.com/segmentio/kafka-go)   | ✅         |

HTTPS instrumentation is limited to Go programs and libraries/languages using libssl3.

## Kubernetes

You can just trigger the Kubernetes descriptors in the `deployments/` folder.

1. Provide your Grafana credentials. Use the following [K8s Secret template](deployments/01-grafana-credentials.template.yml)
   to introduce the endpoints, usernames and API keys for Mimir and Tempo:
   ```
   $ cp deployments/01-grafana-credentials.template.yml 01-grafana-credentials.yml
   $ # EDIT the fields
   $ vim 01-grafana-credentials.yml
   $ kubectl apply -f 01-grafana-credentials.yml 
   ```
2. Deploy the Grafana Agent:
   ```
   kubectl apply -f deployments/02-grafana-agent.yml
   ```

3. Deploy a demo app with the auto-instrumenter as a sidecar. You can use the blog example in the
   [deployments/03-instrumented-app.yml](./deployments/03-instrumented-app.yml) file.
   
   ```
   $ kubectl apply -f ./deployments/03-instrumented-app.yml
   $ kubectl port-forward service/goblog 8443:8443
   ```

You should be able to query traces and metrics in your Grafana board.

## Building Beyla from scratch

### Development environment requirements

#### Required tools
- [mise](https://mise.jdx.dev/) (installs Beyla's pinned Go and native eBPF toolchains)
- GNU make, for invoking the pinned OBI submodule's BPF-generation interface

After cloning the repository, install the complete pinned toolchain across the
repository's Mise roots with:

```shell
mise install --monorepo
```

When a task needs a pinned tool that is not installed yet, Mise installs it
automatically. In CI, jobs select exact tool sets through named profiles in the
[shared setup action](.github/actions/setup-mise/README.md). For environment
overrides, set variables before the task, for example
`GOOS=darwin GOARCH=arm64 mise run compile`. Task arguments go after the task
name, for example `mise run test:shard --shard-id 1 --packages ./pkg`;
do not use `KEY=value` task arguments to set environment variables. Normal
`[env]` defaults treat an empty value as omitted, while build-only
`GOOS`/`GOARCH` overrides preserve an explicitly empty value.

Docker is optional for local development. It is used by Docker-based generation
and image-building tasks, but Beyla's default development workflow generates
BPF bindings with the pinned native Clang/LLVM tools managed by Mise.

#### Common Mise tasks

Beyla's `mise.toml` and `.mise/` tasks are the authoritative development interface.
The default build flow is:

- `mise run build` - generate and vendor OBI dependencies with pinned native tools, then verify and compile Beyla
- `mise run dev` - prepare prerequisites, vendor OBI, and compile a coverage-enabled Beyla binary
- `mise run generate` - regenerate OBI and Beyla eBPF bindings with pinned native tools
- `mise run generate:docker` - optionally regenerate eBPF bindings using the Docker generator image
- `mise run compile` - compile the `beyla` binary
- `mise run lint` and `mise run test` - lint and test the code
- `mise run install:hooks` - install the hk pre-commit hook for C/C++ formatting
- `mise run //java:build` - build the Java agent with the Java project's pinned tools
- `mise run //oats:test:ai` - run the OATS AI suite from its project-owned task config

The root `Makefile` remains available as a compatibility interface. GNU Make is
also used at the OBI submodule boundary to invoke OBI's own BPF generation
interface. New Beyla workflows and automation should use `mise run <task>`.

Legacy `make <target>` commands forward each target to its corresponding Mise
task. GNU Make exports command-line variable assignments to the task (for
example, `make compile CMD=beyla`). Each explicit goal starts its own Mise
invocation; repeated goals are deduplicated by GNU Make, but dependencies shared
across different goals are not. `make -jN` only limits how many forwarded goal
recipes run concurrently; it does not control parallelism inside a Mise task or
preserve GNU Make's full dependency graph and jobserver semantics. Use
`mise run --jobs N <task>` to control Mise task concurrency. Recursive OBI Make
calls through the wrapper may warn that the Make jobserver is unavailable.
`make -n` prints the forwarding command without running it. The exception is
`make run-integration-test-vm`, which directly invokes its script so it can run
in VM images without Mise.

A fresh clone's normal build vendors OBI and its generated BPF bindings as
ignored build artifacts before compiling. Prerequisite setup no longer installs
a Git hook: install it explicitly with `mise run install:hooks`. The old
`check-license` no-op is now a real third-party license check; use
`mise run check:licenses` (or the Make compatibility target).

####  Quickstart

```
$ git clone https://github.com/grafana/beyla.git
$ cd beyla/
$ mise install
$ mise run build
```

`mise run build` vendors OBI using pinned native Clang/LLVM tools, runs the
standard verification suite, and compiles Beyla. Install the hk pre-commit hook
separately with `mise run install:hooks`. Use `mise run dev`
when you specifically need a coverage-enabled binary.

After a successful compilation, binaries can be found in the `bin/` subdirectory.

#### Managing code dependencies to opentelemetry-ebpf-instrumentation

Beyla vendors part of the code from the [opentelemetry-ebpf-instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation)
(OBI) project.

The code is incorporated as a Git submodule, named `obi-src`, in the `.obi-src` folder in the Beyla code base.
The contents of the `.obi-src` are used to build the BPF dependencies, and in a second step they are vendored
in the `vendor/` directory.

Usually, run `mise run vendor:obi` to generate OBI bindings with Beyla’s pinned native Clang/LLVM tools and vendor them locally. This task invokes GNU Make only at the OBI submodule boundary, where Make is OBI’s own BPF-generation interface.

`.obi-src` folder is pinned to a concrete version of the OBI Git history. If you did changes in the upstream
[opentelemetry-ebpf-instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation)
repository, and want to update `.obi-src` to the latest contents, you'll need to run, from Beyla's project folder:

```
git submodule update --checkout --remote 
git add .
```

(`git add .` is really important, otherwise when you try to recompile the code, the `obi-src` submodule might be
reverted to its original status).

#### Developing with a local, development branch of opentelemetry-ebpf-instrumentation

Temporarily go to `go.mod` and change the first `replace` directive by your local OBI folder. For example:

```diff
-replace go.opentelemetry.io/obi => ./.obi-src
+replace go.opentelemetry.io/obi => ../opentelemetry-ebpf-instrumentation
```

Build the docker image with `mise run image:dev-build`.

⚠️ Before pushing your changes to our GitHub repo, don't forget to revert the `replace` directive in `go.mod`! 

#### Formatting and linting code

Beyla uses hk to orchestrate its Go linting and formatting checks:
- `golangci-lint` for Go linting and the repository's gofmt/gci import formatting rules
- `clang-format` for staged C/C++ formatting in the hk pre-commit hook
- `clang:tidy` for static analysis of the C code

Go linting and formatting are checked on pull requests. You can invoke the checks and formatters manually:

- `mise run lint` runs the configured Go checks through hk; dashboard linting runs separately in CI with Grafana's pinned dashboard-linter action
- `mise run lint:fix` applies Go formatting without staging changes
- `mise run clang:tidy` invokes `clang:tidy` on the C/eBPF code

The hk pre-commit hook checks the root Go module when Go files are staged and
applies C/C++ formatting to staged files. Run `mise run fmt` for Go formatting
and `mise run clang:format` for C/C++ formatting.

#### Running VM tests

In addition to the `test` and `integration-test` `Makefile` targets, Beyla also runs select tests on QEMU virtual machines in order to be able to test different kernel versions. These tests are also part of our GitHub workflow, but it is also possible to run them manually using the following command:

```
$ sudo make -C internal/testgenerated/vm KERNEL_VER=...
```

where `KERNEL_VER` is one of the supported kernel versions located in `internal/testgenerated/vm/kernels`. For example, to run tests against kernel version 5.15.152, simply do:

```
$ sudo make -C internal/testgenerated/vm KERNEL_VER=5.15.152
```

## Credits

Part of the code is taken from: https://github.com/open-telemetry/opentelemetry-go-instrumentation


