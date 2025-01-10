# Use Beyla in Grafana Alloy in Kubernetes

This example demonstrates how to instrument a sample application running in Kubernetes with Beyla using [Grafana Alloy](https://github.com/grafana/alloy) and sending metrics and traces to Grafana Cloud.

1. Replace your Grafana Cloud credentials for Prometheus and Tempo remote write in `secrets.yml`
2. Run `kubectl apply -f sampleapps.yml` and `kubectl apply -f secrets.yml`
3. Create ConfigMap with Alloy config: `kubectl create configmap --namespace alloy alloy-config "--from-file=config.alloy=./config.alloy"`
4. Run `helm install --namespace alloy alloy grafana/alloy` to setup the Alloy.
5. Deploy Alloy with Helm using `helm upgrade --namespace alloy alloy grafana/alloy -f values.yaml`
