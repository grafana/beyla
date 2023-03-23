# Main binary configuration
CMD ?= otelhttp
MAIN_GO_FILE ?= cmd/$(CMD).go
GOOS ?= linux
GOARCH ?= amd64

# TODO: grafana
DOCKERHUB_USER ?= mariomac

COMPOSE_ARGS ?= -f test/integration/docker-compose.yml
COMPOSE_LOGS ?= docker-compose.log

# Container image creation creation
VERSION ?= latest
IMAGE_TAG_BASE ?= $(DOCKERHUB_USER)/http-autoinstrument
IMG ?= $(IMAGE_TAG_BASE):$(VERSION)

# The generator is a local container image that provides a reproducible environment for
# building eBPF binaries
GEN_IMAGE_TAG_BASE ?= $(DOCKERHUB_USER)/ebpf-generator
GEN_IMG ?= $(GEN_IMAGE_TAG_BASE):$(VERSION)

OCI_BIN ?= docker

GOLANGCI_LINT_VERSION = v1.51.2

# BPF code generator dependencies
CILIUM_EBPF_VERSION := v0.10.0
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES="(/cmd/)|(bpf_bpfe)|(/pingserver/)|(/test/collector/)"

.DEFAULT_GOAL := all
# Oneshell is required to auto-cleanup of integration tests
export SHELL:=/bin/sh
export SHELLOPTS:=$(if $(SHELLOPTS),$(SHELLOPTS):)pipefail:errexit
.ONESHELL:

.PHONY: prereqs
prereqs:
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	test -f $(shell go env GOPATH)/bin/golangci-lint || GOFLAGS="" go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}
	test -f $(shell go env GOPATH)/bin/bpf2go || go install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}
#	test -f $(shell go env GOPATH)/bin/kind || go install sigs.k8s.io/kind@latest

.PHONY: lint
lint: prereqs
	@echo "### Linting code"
	golangci-lint run ./... --timeout=3m

# As generated artifacts are part of the code repo (pkg/ebpf packages), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder.
# You might want to use the docker-generate target instead of this.
.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: prereqs
	@echo "### Generating BPF Go bindings"
	go generate ./pkg/...


.PHONY: docker-generate
docker-generate:
	$(OCI_BIN) run --rm -v $(shell pwd):/src $(GEN_IMG)

.PHONY: verify
verify: prereqs lint test

.PHONY: build
build: verify compile

.PHONY: all
all: generate build

.PHONY: compile
compile:
	@echo "### Compiling project"
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -mod vendor -ldflags -a -o bin/$(CMD) $(MAIN_GO_FILE)

.PHONY: test
test:
	@echo "### Testing code"
	go test -mod vendor -a ./... -coverpkg=./... -coverprofile cover.all.out

.PHONY: cov-exclude-generated
cov-exclude-generated:
	grep -vE $(EXCLUDE_COVERAGE_FILES) cover.all.out > cover.out

.PHONY: coverage-report
coverage-report: cov-exclude-generated
	@echo "### Generating coverage report"
	go tool cover --func=./cover.out

.PHONY: coverage-report-html
coverage-report-html: cov-exclude-generated
	@echo "### Generating HTML coverage report"
	go tool cover --html=./cover.out

.PHONY: image-build-push
image-build-push: ## Build OCI image with the manager.
	$(OCI_BIN) buildx build --push --platform linux/amd64,linux/arm64 -t ${IMG} .

.PHONY: generator-image-build-push
generator-image-build-push: ## Build OCI image with the manager.
	@echo "### Creating the image that generates the eBPF binaries"
	$(OCI_BIN) buildx build . --push -f generator.Dockerfile --platform linux/amd64,linux/arm64 -t $(GEN_IMG)

.PHONY: prepare-integration-test
prepare-integration-test:
	@echo "### Removing resources from previous integration tests, if any"
	$(OCI_BIN) compose $(COMPOSE_ARGS) stop || true
	$(OCI_BIN) compose $(COMPOSE_ARGS) rm -f || true
	$(OCI_BIN) rmi -f $(shell $(OCI_BIN) images --format '{{.Repository}}:{{.Tag}}' | grep 'hatest-') || true
	@echo "### Spinning up Compose cluster"
	$(OCI_BIN) compose $(COMPOSE_ARGS)  up --detach

.PHONY: cleanup-integration-test
cleanup-integration-test:
	@echo "### Storing integration tests Compose logs"
	$(OCI_BIN) compose $(COMPOSE_ARGS) logs > $(COMPOSE_LOGS)
	@echo "### Removing integration test Compose cluster"
	$(OCI_BIN) compose $(COMPOSE_ARGS) stop
	$(OCI_BIN) compose $(COMPOSE_ARGS) rm -f

# TODO: provide coverage info for integration testing https://go.dev/blog/integration-test-coverage
.PHONY: run-integration-test
run-integration-test:
	@echo "### Running integration tests"
	go clean -testcache
	go test -mod vendor -a ./test/integration/... --tags=integration

.PHONY: integration-test
integration-test: prepare-integration-test
	$(MAKE) run-integration-test || (ret=$$?; $(MAKE) cleanup-integration-test && exit $$ret)
	$(MAKE) cleanup-integration-test
