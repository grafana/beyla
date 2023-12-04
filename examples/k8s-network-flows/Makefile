IMG ?= beyla-local:netobserv

build:
	@echo "building beyla"
	pushd ../.. && docker build -t $(IMG) . && popd

kind-load:
	@echo "loading beyla image into kind"
	kind -n network-observability-testbed load docker-image $(IMG)

kind:
	@echo "recreating kind cluster"
	kind delete cluster -n network-observability-testbed || true
	kind create cluster -n network-observability-testbed

k8s-apply:
	@echo "applying all the k8s manifests"
	kubectl apply -f 01-permissions.yml
	kubectl apply -f 02-testapp.yml
	kubectl apply -f 03-beyla.yml

k8s-delete:
	@echo "deleting all the k8s manifests"
	kubectl delete -f 01-permissions.yml
	kubectl delete -f 02-testapp.yml
	kubectl delete -f 03-beyla.yml

.PHONY: build kind kind-load k8s-apply k8s-delete
