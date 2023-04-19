# Quick start tutorial

The eBPF autoinstrumenter allows reporting basic traces information as well as
[RED metrics](https://grafana.com/files/grafanacon_eu_2018/Tom_Wilkie_GrafanaCon_EU_2018.pdf)
for Go HTTP/S and GRPC services in Linux, without requiring to modify the code
to manually insert probes.

The eBPF autoinstrumenter requires Linux with Kernel 4.18 or higher, with eBPF
enabled.

## Downloading

ℹ️ _For help about how to download and run the autoinstrumenter as a container, you
can check the documentation about [running the eBPF autoinstrumenter as a Docker container](docker.md)
or [running the eBPF autoinstrumenter in Kubernetes](k8s.md)._

You can download the instrumenter executable with Go get:

```
go get github.com/grafana/ebpf-autoinstrument@latest
```

## TO DO
