# Main binary configuration
CMD ?= otelauto
MAIN_GO_FILE ?= cmd/$(CMD)/main.go
GOOS ?= linux
GOARCH ?= amd64

TEST_OUTPUT ?= ./testoutput

IMG_REGISTRY ?= docker.io
# Set your registry username. CI will set 'grafana' but you mustn't use it for manual pushing.
IMG_ORG ?=
IMG_NAME ?= ebpf-autoinstrument
# Container image creation creation
VERSION ?= dev
IMG = $(IMG_REGISTRY)/$(IMG_ORG)/$(IMG_NAME):$(VERSION)

# The generator is a local container image that provides a reproducible environment for
# building eBPF binaries
GEN_IMG_NAME ?= ebpf-generator
GEN_IMG ?= $(GEN_IMG_NAME):$(VERSION)

COMPOSE_ARGS ?= -f test/integration/docker-compose.yml

OCI_BIN ?= docker
DRONE ?= drone

# BPF code generator dependencies
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES="(bpf_)|(/pingserver/)|(/test/collector/)"

.DEFAULT_GOAL := all

# go-install-tool will 'go install' any package $2 and install it locally to $1.
# This will prevent that they are installed in the $USER/go/bin folder and different
# projects ca have different versions of the tools
PROJECT_DIR := $(shell dirname $(abspath $(firstword $(MAKEFILE_LIST))))

TOOLS_DIR ?= $(PROJECT_DIR)/bin

define go-install-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(TOOLS_DIR) GOFLAGS="-mod=mod" go install $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

# Check that given variables are set and all have non-empty values,
# die with an error otherwise.
#
# Params:
#   1. Variable name(s) to test.
#   2. (optional) Error message to print.
check_defined = \
    $(strip $(foreach 1,$1, \
        $(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
    $(if $(value $1),, \
      $(error Undefined $1$(if $2, ($2))))

# prereqs binary dependencies
GOLANGCI_LINT = $(TOOLS_DIR)/golangci-lint
BPF2GO = $(TOOLS_DIR)/bpf2go
GO_OFFSETS_TRACKER = $(TOOLS_DIR)/go-offsets-tracker

.PHONY: prereqs
prereqs:
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	mkdir -p $(TEST_OUTPUT)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2)
	$(call go-install-tool,$(BPF2GO),github.com/cilium/ebpf/cmd/bpf2go@v0.10.0)
	$(call go-install-tool,$(GO_OFFSETS_TRACKER),github.com/grafana/go-offsets-tracker/cmd/go-offsets-tracker@v0.1.4)

.PHONY: lint
lint: prereqs
	@echo "### Linting code"
	$(GOLANGCI_LINT) run ./... --timeout=3m

.PHONY: update-offsets
update-offsets: prereqs
	@echo "### Updating pkg/goexec/offsets.json"
	$(GO_OFFSETS_TRACKER) -i configs/offsets/tracker_input.json pkg/goexec/offsets.json

# As generated artifacts are part of the code repo (pkg/ebpf packages), you don't have
# to run this target for each build. Only when you change the C code inside the bpf folder.
# You might want to use the docker-generate target instead of this.
.PHONY: generate
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: export BPF2GO := $(BPF2GO)
generate: prereqs
	@echo "### Generating BPF Go bindings"
	go generate ./pkg/...

.PHONY: docker-generate
docker-generate:
	$(OCI_BIN) run --rm -v $(shell pwd):/src $(GEN_IMG)

.PHONY: verify
verify: prereqs lint #test

.PHONY: build
build: verify compile

.PHONY: all
all: generate build

.PHONY: compile
compile:
	@echo "### Compiling project"
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -mod vendor -ldflags -a -o bin/$(CMD) $(MAIN_GO_FILE)

# Generated binary can provide coverage stats according to https://go.dev/blog/integration-test-coverage
.PHONY: compile-for-coverage
compile-for-coverage:
	@echo "### Compiling project to generate coverage profiles"
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -mod vendor -cover -a -o bin/$(CMD) $(MAIN_GO_FILE)

.PHONY: test
test:
	@echo "### Testing code"
	go test -mod vendor -a ./... -coverpkg=./... -coverprofile $(TEST_OUTPUT)/cover.all.txt

.PHONY: cov-exclude-generated
cov-exclude-generated:
	grep -vE $(EXCLUDE_COVERAGE_FILES) $(TEST_OUTPUT)/cover.all.txt > $(TEST_OUTPUT)/cover.txt

.PHONY: coverage-report
coverage-report: cov-exclude-generated
	@echo "### Generating coverage report"
	go tool cover --func=$(TEST_OUTPUT)/cover.txt

.PHONY: coverage-report-html
coverage-report-html: cov-exclude-generated
	@echo "### Generating HTML coverage report"
	go tool cover --html=$(TEST_OUTPUT)/cover.txt

.PHONY: image-build-push
image-build-push:
	@echo "### Building and pushing the auto-instrumenter image"
	$(call check_defined, IMG_ORG, Your Docker repository user name)
	$(OCI_BIN) buildx build --push --platform linux/amd64,linux/arm64 -t ${IMG} .

.PHONY: generator-image-build
generator-image-build:
	@echo "### Creating the image that generates the eBPF binaries"
	$(OCI_BIN) build . -f generator.Dockerfile -t $(GEN_IMG)

.PHONY: prepare-integration-test
prepare-integration-test:
	@echo "### Removing resources from previous integration tests, if any"
	rm -rf $(TEST_OUTPUT)/* || true
	$(MAKE) cleanup-integration-test

.PHONY: cleanup-integration-test
cleanup-integration-test:
	@echo "### Removing integration test Compose cluster"
	$(OCI_BIN) compose $(COMPOSE_ARGS) stop || true
	$(OCI_BIN) compose $(COMPOSE_ARGS) rm -f || true
	$(OCI_BIN) rmi -f $(shell $(OCI_BIN) images --format '{{.Repository}}:{{.Tag}}' | grep 'hatest-') || true

.PHONY: run-integration-test
run-integration-test:
	@echo "### Running integration tests"
	go clean -testcache
	go test -mod vendor -a ./test/integration/... --tags=integration

.PHONY: integration-test
integration-test: prereqs prepare-integration-test
	$(MAKE) run-integration-test || (ret=$$?; $(MAKE) cleanup-integration-test && exit $$ret)
	$(MAKE) itest-coverage-data
	$(MAKE) cleanup-integration-test

.PHONY: itest-coverage-data
itest-coverage-data:
	# merge coverage data from all the integration tests
	mkdir -p $(TEST_OUTPUT)/merge
	go tool covdata merge -i=$(TEST_OUTPUT) -o $(TEST_OUTPUT)/merge
	go tool covdata textfmt -i=$(TEST_OUTPUT)/merge -o $(TEST_OUTPUT)/itest-covdata.raw.txt
	# replace the unexpected /src/cmd/otelauto/main.go file by the module path
	sed 's/^\/src\/cmd\//github.com\/grafana\/ebpf-autoinstrument\/cmd\//' $(TEST_OUTPUT)/itest-covdata.raw.txt > $(TEST_OUTPUT)/itest-covdata.all.txt
	# exclude generated files from coverage data
	grep -vE $(EXCLUDE_COVERAGE_FILES) $(TEST_OUTPUT)/itest-covdata.all.txt > $(TEST_OUTPUT)/itest-covdata.txt

.PHONY: drone
drone:
	@echo "### Regenerating and signing .drone/drone.yml"
	drone jsonnet --format --stream --source .drone/drone.jsonnet --target .drone/drone.yml
	drone lint .drone/drone.yml
	drone sign --save grafana/ebpf-autoinstrument .drone/drone.yml || echo "You must set DRONE_SERVER and DRONE_TOKEN. These values can be found on your [drone account](http://drone.grafana.net/account) page."

.PHONY: check-drone-drift
check-drone-drift:
	@echo "### checking that Drone.yml is up-to-date"
	./scripts/check-drone-drift.sh