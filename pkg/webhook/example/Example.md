# Running the Beyla example Kubernetes cluster with the webhook

## Make a cluster

### 1. Install Kind
https://kind.sigs.k8s.io/docs/user/quick-start/

### 2. Create a new kind cluster
```sh
kind create cluster
```

### 3. Install cert manager
Cert manager gives Beyla certificate for the webhook. The webhook runs over TLS and it needs certificates that Kubernetes will recognize.

```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
```

then wait until it's done:

```sh
kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=120s
```

verify with:
```sh
kubectl get pods -n cert-manager
```

## Build Beyla from the Dockerfile and Add to the cluster
The beyla.yaml file pulls from a local Beyla image that we build from this branch. So we need to build a local Beyla image like this:

In the Beyla source dir:
```sh
docker build -t beyla:local -f Dockerfile .
```

Next we need to load this local build to Kind as a known image:

```sh
kind load docker-image beyla:local
```

## Run Docker LGTM

Run an instance of Docker LGTM so we can get a full Observability Cluster
The Beyla daemonset exports to:

```yaml
            - name: OTEL_EXPORTER_OTLP_ENDPOINT
              value: "http://172.17.0.1:4318"
```
which is the host IP address for the Kind cluster. If you run Docker lgtm 
on your localhost, the exported traces and metrics will directly reach it.

## Install Beyla and then the Apps

### 1. Install your local Beyla build in the K8s cluster

```sh
kubectl apply -f beyla.yaml
```

### 2. Install the sample apps

```sh
kubectl apply -f apps.yaml
```

You can use [k9s](https://k9scli.io) to check the Beyla logs that will be printing messages of all the pods they have instrumented. We should instrument both the nodejs and the java app.

You can also check the Beyla pod logs with `kubectl`.

## Testing the instrumentation

### 1. Open the port to the Node.js frontend application

```sh
kubectl port-forward svc/frontend 8080:8080
```

### 2. Run curl to send some traffic

```sh
curl "http://localhost:8080/suggestion?language=english&gender=boy"
```

After this point you should see some traces appear in your Tempo in LGTM.

## Testing a new image (after making changes or debugging)

I usually delete the prior deployments and install fresh, like this:
```sh
kubectl delete -f apps.yaml
kubectl delete -f beyla.yaml
```

Then once you build a new Beyla docker image, you must load this new image to kind again with:

```sh
kind load docker-image beyla:local
```

And repeat the step of deploying Beyla and then the apps.
