# GPU metrics builds

AMD and Intel collection reads host sysfs with the standard Beyla build.
NVIDIA collection loads NVML at runtime. Build it with:

```sh
make compile BUILD_TAGS=beyla_nvml
```

The NVIDIA binary uses the system dynamic loader and glibc even with
`CGO_ENABLED=0`. Build a container with a glibc runtime:

```sh
docker build --build-arg BUILD_TAGS=beyla_nvml \
  --build-arg RUNTIME_IMG=debian:bookworm-slim -t beyla-gpu .
```

Run with NVIDIA Container Toolkit, GPU device access, and the `utility` driver
capability so that `libnvidia-ml.so.1` is available. Preserve the permissions and
host mounts required by your Beyla deployment. The default container build
continues to use scratch and excludes the NVML backend.

Run the sysfs-to-Prometheus HTTP integration test without GPU hardware:

```sh
make test-gpu-integration
make test-gpu-integration BUILD_TAGS=beyla_nvml
```

These tests exercise discovery, metric conversion, changing readings and missing
readings. They do not validate NVIDIA driver calls or real GPU hardware.

The NVML integration test compiles a fixture shared library with `cc` and loads
it through purego in a child process. It requires Linux and glibc, but no NVIDIA
GPU or installed driver:

```sh
make test-gpu-nvml-integration
```

It checks discovery, memory and utilization readings, power conversion, missing
optional symbols, unsupported readings, and initialization errors.
