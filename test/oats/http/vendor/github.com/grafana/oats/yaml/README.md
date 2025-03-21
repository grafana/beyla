# Declarative Yaml tests

You can use declarative yaml tests in `oats.yaml` files:

> You can use any file name that matches `oats*.yaml` (e.g. `oats-test.yaml`), that doesn't end in `-template.yaml`.
> `oats-template.yaml` is reserved for template files, which are used in the "include" section.

The syntax is a bit similar to https://github.com/kubeshop/tracetest

This is an example:

```yaml
include:
  - ../oats-template.yaml
docker-compose:
  generator: java
  file: ../docker-compose.yaml
  resources:
    - kafka
input:
  - url: http://localhost:8080/stock
interval: 500ms
expected:
  traces:
    - traceql: '{ name =~ "SELECT .*product"}'
      spans:
        - name: 'regex:SELECT .*'
          attributes:
            db.system: h2
  logs:
    - logql: '{exporter = "OTLP"}'
      contains: 
        - 'hello LGTM'
  metrics:
    - promql: 'db_client_connections_max{pool_name="HikariPool-1"}'
      value: "== 10"
  dashboards:
    - path: ../jdbc-dashboard.json
      panels:
        - title: Connection pool waiting requests
          value: "== 0"
        - title: Connection pool utilization
          value: "> 0"
```

You have to provide the root path of the directory where your test cases are located to ginkgo
via the environment variable `TESTCASE_BASE_PATH`.

## Docker Compose

Describes the docker-compose file(s) to use for the test.
The files typically defines the instrumented application you want to test and optionally some dependencies,
e.g. a database server to send requests to.
You don't need (and should have) to define the observability stack (e.g. prometheus, grafana, etc.),
because this is provided by the test framework (and may test different versions of the observability stack,
e.g. otel collector and grafana agent).

This docker-compose file is relative to the `oats.yaml` file.
If you're referencing other configuration files, you can use the `resources` field to specify them.

### Generators

Generators can be used to generate a docker-compose file from a template as a way to avoid repetition.

Currently, the only defined generator is `java` which generates a docker-compose file for the java distribution
examples.
Using an undefined generator name (e.g.) `name` will result in using the file `docker-compose-name-template.yml`
and performing template variable substitution, with the vars as seen in this excerpt of generateDockerComposeFile() in generator.go:
```
	vars["Dashboard"] = filepath.ToSlash(dashboard)
	vars["ConfigDir"] = filepath.ToSlash(configDir)
	vars["ApplicationPort"] = c.PortConfig.ApplicationPort
	vars["GrafanaHTTPPort"] = c.PortConfig.GrafanaHTTPPort
	vars["PrometheusHTTPPort"] = c.PortConfig.PrometheusHTTPPort
	vars["LokiHTTPPort"] = c.PortConfig.LokiHTTPPort
	vars["TempoHTTPPort"] = c.PortConfig.TempoHTTPPort
```
Additional variables could be added for more specific generators as needed. (e.g. add new case in getTemplateVars() that adds more vars.)

When a generator is used, template variable interpolation will also occur on all docker-compose file(s).
        
## Matrix of test cases

Matrix tests are useful to test different configurations of the same application, 
e.g. with different settings of the otel collector or different flags in the application.

```yaml
matrix:
  - name: new
    docker-compose:
      generator: java
  - name: old-jvm-metrics
    docker-compose:
      generator: java
      java-generator-params:
        old-jvm-metrics: true
        disable-data-saver: true
  - name: prom-naming
    docker-compose:
      generator: java
      java-generator-params:
        disable-data-saver: true
        prom-naming: true
  - name: prom-naming-old-jvm-metrics
    docker-compose:
      generator: java
      java-generator-params:
        disable-data-saver: true
        old-jvm-metrics: true
        prom-naming: true
input:
  - path: /stock
```

## Starting the Tests

The java distribution is used as an example here, but you can use any other example.

```sh
TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r
```

If you want to run a single test case, you can use the `--focus` option:

```sh
TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r --focus="jdbc"
```

You can increase the timeout, which is useful if you want to inspect the telemetry data manually
in grafana at http://localhost:3000

```sh
TESTCASE_TIMEOUT=1h TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r
```

You can also run the tests in parallel:

```sh
TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r -p
```
                             
You can keep the container running without executing the tests - which is useful to debug in grafana manually:

```sh
TESTCASE_MANUAL_DEBUG=true TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r
```

### Java specific options

If you don't want to build the java examples, you can use the `TESTCASE_SKIP_BUILD` environment variable:

```sh
TESTCASE_SKIP_BUILD=true TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r
```

If you want to attach a debugger to the java application, you can use the `TESTCASE_JVM_DEBUG` environment variable:

```sh
TESTCASE_JVM_DEBUG=true TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r
```

If you want to enable all instrumentations (including the ones that are disabled by default), you can use the `TESTCASE_INCLUDE_ALL_INSTRUMENTATIONS` environment variable:

```sh
TESTCASE_INCLUDE_ALL_INSTRUMENTATIONS=true TESTCASE_BASE_PATH=/path/to/grafana-opentelemetry-java/examples ginkgo -v -r
```
You can then attach a debugger to the java application at port 5005.
