# Main binary configuration
CMD ?= main
MAIN_GO_FILE ?= cmd/$(CMD).go
GOOS ?= linux
GOARCH ?= amd64

DOCKERHUB_USER ?= $(USER)

# Container image creation creation
VERSION ?= latest
IMAGE_TAG_BASE ?= $(DOCKERHUB_USER)/ebpf-template
IMG ?= $(IMAGE_TAG_BASE):$(VERSION)

# The generator is a local container image that provides a reproducible environment for
# building eBPF binaries
# TODO: consider moving it to its own shared project and
LOCAL_GENERATOR_IMAGE ?= ebpf-generator:latest

LOCAL_E2E_TEST_IMAGE ?= localhost/ebpf-agent:test

OCI_BIN ?= docker

GOLANGCI_LINT_VERSION = v1.50.1

# BPF code generator dependencies
CILIUM_EBPF_VERSION := v0.10.0
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# regular expressions for excluded file patterns
# TODO: change
EXCLUDE_COVERAGE_FILES="(/cmd/)|(bpf_bpfe)|(/examples/)|(/pkg/pbflow/)"

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

.PHONY: docker-generator-build
docker-generator-build:
	@echo "### Creating the container that generates the eBPF binaries"
	$(OCI_BIN) buildx build . -f scripts/generators.Dockerfile -t $(LOCAL_GENERATOR_IMAGE)

.PHONY: docker-generate
docker-generate:
	$(OCI_BIN) run --rm -v $(shell pwd):/src $(LOCAL_GENERATOR_IMAGE)

.PHONY: build
build: prereqs lint test compile

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

.PHONY: image-push
image-push: ## Push OCI image with the manager.
	$(OCI_BIN) push ${IMG}

