---
title: "Quickstart: instrument a Go service with Beyla"
menuTitle: Go quickstart
description: Learn how to quickly set up and run Beyla to instrument a Go service
weight: 2
keywords:
  - Beyla
  - eBPF
  - Go
  - Golang
---

# Quickstart: instrument a Go service with Beyla

## 1. Run your instrumentable Go service

You can use any Go service of your own. For testing purposes, you can also download and run this
[simple Go HTTP service](https://raw.githubusercontent.com/grafana/beyla/main/examples/quickstart/golang/quickstart.go).

```
curl -OL https://raw.githubusercontent.com/grafana/beyla/main/examples/quickstart/golang/quickstart.go
go run quickstart.go
```

## 2. Download Beyla

You can download the latest Beyla executable from the [Beyla releases page](https://github.com/grafana/beyla/releases).
Uncompress and copy the Beyla executable to any location in your `$PATH`.

As an alternative (if your host has the Go toolset installed), you can directly download the
Beyla executable with the `go install` command:

```sh
go install github.com/grafana/beyla/cmd/beyla@latest
```

## 3. (Optional) get your Grafana Cloud credentials

Beyla can export metrics and traces to any OpenTelemetry endpoint, as well as exposing
metrics as a Prometheus endpoint. However, we recommend using the OpenTelemetry
endpoint in Grafana Cloud. You can get a [Free Grafana Cloud Account at Grafana's website](/pricing/).

In your Grafana Cloud Portal, click on the "Details" button in the "OpenTelemetry" box. Next,
copy your Grafana OTLP Endpoint and Instance ID, as in the image below.

![](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/otlp-connection-details.png)

Also generate a Password/API token with metrics push privileges.

## 4. Run Beyla with minimal configuration

To run Beyla, you will require to set the following environment variables:

* `BEYLA_OPEN_PORT`: the port where your instrumented service is listening
  (for example, `80` or `443`). If you are using the example service in the
  first section of this guide, you need to set this variable to `8080`.
* `OTEL_EXPORTER_OTLP_ENDPOINT`: the OpenTelemetry endpoint URL, as obtained
  in the previous section (for example: `https://otlp-gateway-prod-eu-west-0.grafana.net/otlp`)
* `GRAFANA_CLOUD_INSTANCE_ID`: the Grafana Cloud Username / Instance ID, as
  obtained in the previous section.
* `GRAFANA_CLOUD_API_KEY`: your Grafana Cloud API Key.

To facilitate local testing, we will also set the `PRINT_TRACES=true` environment
variable. This will print the traces of your instrumented service in the standard output
of Beyla.

Please notice that Beyla requires to run with administrative privileges.

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp-gateway-prod-eu-west-0.grafana.net/otlp
export GRAFANA_CLOUD_INSTANCE_ID=123456
export GRAFANA_CLOUD_API_KEY="your api key here..."
export BEYLA_OPEN_PORT=8080
export PRINT_TRACES=true

sudo -E beyla
```

## 5. Test your service

Having either your service running (step 1) and Beyla running (step 4), you can do
some HTTP requests to the instrumented service. For example:


