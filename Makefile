# Main binary configuration
CMD ?= beyla
MAIN_GO_FILE ?= cmd/$(CMD)/main.go
GOOS ?= linux
GOARCH ?= amd64

# DRONE_TAG is set from Drone. Required for building container images.
RELEASE_VERSION := $(if $(DRONE_TAG),$(DRONE_TAG),$(shell git describe --tags --always))
RELEASE_REVISION := $(shell git rev-parse --short HEAD )
BUILDINFO_PKG ?= github.com/grafana/beyla/pkg/buildinfo
TEST_OUTPUT ?= ./testoutput

IMG_REGISTRY ?= docker.io
# Set your registry username. CI will set 'grafana' but you mustn't use it for manual pushing.
IMG_ORG ?=
IMG_NAME ?= beyla
# Container image creation creation
VERSION ?= dev
IMG = $(IMG_REGISTRY)/$(IMG_ORG)/$(IMG_NAME):$(VERSION)

# The generator is a container image that provides a reproducible environment for
# building eBPF binaries
GEN_IMG ?= ghcr.io/grafana/beyla-generator:main

COMPOSE_ARGS ?= -f test/integration/docker-compose.yml

OCI_BIN ?= docker
DRONE ?= drone

# BPF code generator dependencies
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# regular expressions for excluded file patterns
EXCLUDE_COVERAGE_FILES="(bpfel_)|(/pingserver/)|(/grafana/beyla/test/)|(integration/components)|(/grafana/beyla/docs/)|(/grafana/beyla/configs/)|(/grafana/beyla/examples/)"

.DEFAULT_GOAL := all

# go-install-tool will 'go install' any package $2 and install it locally to $1.
# This will prevent that they are installed in the $USER/go/bin folder and different
# projects ca have different versions of the tools
PROJECT_DIR := $(shell dirname $(abspath $(firstword $(MAKEFILE_LIST))))

TOOLS_DIR ?= $(PROJECT_DIR)/bin

# $(1) command name
# $(2) repo URL
# $(3) version
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Removing any outdated version of $(1)";\
rm -f $(1)*;\
echo "Downloading $(2)@$(3)" ;\
GOBIN=$(TOOLS_DIR) GOFLAGS="-mod=mod" go install "$(2)@$(3)" ;\
touch "$(1)-$(3)";\
rm -rf $$TMP_DIR ;\
}
endef

# gomod-version returns the version number of the go.mod dependency
define gomod-version
$(shell sh -c "echo $$(grep $(1) go.mod | awk '{print $$2}')")
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
GOIMPORTS_REVISER = $(TOOLS_DIR)/goimports-reviser
GO_LICENSES = $(TOOLS_DIR)/go-licenses
KIND = $(TOOLS_DIR)/kind
DASHBOARD_LINTER = $(TOOLS_DIR)/dashboard-linter
GINKGO = $(TOOLS_DIR)/ginkgo

define check_format
	$(shell $(foreach FILE, $(shell find . -name "*.go" -not -path "**/vendor/*"), \
		$(GOIMPORTS_REVISER) -company-prefixes github.com/grafana -list-diff -output stdout $(FILE);))
endef

.PHONY: prereqs
prereqs:
	@echo "### Check if prerequisites are met, and installing missing dependencies"
	mkdir -p $(TEST_OUTPUT)/run
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,v1.57.2)
	$(call go-install-tool,$(BPF2GO),github.com/cilium/ebpf/cmd/bpf2go,$(call gomod-version,cilium/ebpf))
	$(call go-install-tool,$(GO_OFFSETS_TRACKER),github.com/grafana/go-offsets-tracker/cmd/go-offsets-tracker,$(call gomod-version,grafana/go-offsets-tracker))
	$(call go-install-tool,$(GOIMPORTS_REVISER),github.com/incu6us/goimports-reviser/v3,v3.6.4)
	$(call go-install-tool,$(GO_LICENSES),github.com/google/go-licenses,v1.6.0)
	$(call go-install-tool,$(KIND),sigs.k8s.io/kind,v0.20.0)
	$(call go-install-tool,$(DASHBOARD_LINTER),github.com/grafana/dashboard-linter,latest)

.PHONY: fmt
fmt: prereqs
	@echo "### Formatting code and fixing imports"
	@$(foreach FILE, $(shell find . -name "*.go" -not -path "**/vendor/*"), \
		$(GOIMPORTS_REVISER) -company-prefixes github.com/grafana $(FILE);)

.PHONY: checkfmt
checkfmt:
	@echo '### check correct formatting and imports'
	@if [ "$(strip $(check_format))" != "" ]; then \
		echo "$(check_format)"; \
		echo "Above files are not properly formatted. Run 'make fmt' to fix them"; \
		exit 1; \
	fi

.PHONY: lint-dashboard
lint-dashboard: prereqs
	@echo "### Linting dashboard"
	$(DASHBOARD_LINTER) lint grafana/dashboard.json

.PHONY: lint
lint: prereqs checkfmt
	@echo "### Linting code"
	$(GOLANGCI_LINT) run ./... --timeout=6m

.PHONY: update-offsets
update-offsets: prereqs
	@echo "### Updating pkg/internal/goexec/offsets.json"
	$(GO_OFFSETS_TRACKER) -i configs/offsets/tracker_input.json pkg/internal/goexec/offsets.json

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
verify: prereqs lint-dashboard lint test

.PHONY: build
build: verify compile

.PHONY: all
all: generate build

.PHONY: compile
compile:
	@echo "### Compiling project"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -mod vendor -ldflags="-X '$(BUILDINFO_PKG).Version=$(RELEASE_VERSION)' -X '$(BUILDINFO_PKG).Revision=$(RELEASE_REVISION)'" -a -o bin/$(CMD) $(MAIN_GO_FILE)

.PHONY: dev
dev: prereqs generate compile-for-coverage

# Generated binary can provide coverage stats according to https://go.dev/blog/integration-test-coverage
.PHONY: compile-for-coverage
compile-for-coverage:
	@echo "### Compiling project to generate coverage profiles"
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -mod vendor -cover -a -o bin/$(CMD) $(MAIN_GO_FILE)

.PHONY: test
test:
	@echo "### Testing code"
	go test -race -mod vendor -a ./... -coverpkg=./... -coverprofile $(TEST_OUTPUT)/cover.all.txt

.PHONY: test-privileged
test-privileged:
	@echo "### Testing code with privileged tests enabled"
	PRIVILEGED_TESTS=true go test -race -mod vendor -a ./... -coverpkg=./... -coverprofile $(TEST_OUTPUT)/cover.all.txt

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
	@echo "### Removing integration test clusters"
	$(KIND) delete cluster -n test-kind-cluster || true
	@echo "### Removing docker containers and images"
	$(OCI_BIN) compose $(COMPOSE_ARGS) stop || true
	$(OCI_BIN) compose $(COMPOSE_ARGS) rm -f || true
	$(OCI_BIN) rm -f $(shell $(OCI_BIN) ps --format '{{.Names}}' | grep 'integration-') || true
	$(OCI_BIN) rmi -f $(shell $(OCI_BIN) images --format '{{.Repository}}:{{.Tag}}' | grep 'hatest-') || true

.PHONY: run-integration-test
run-integration-test:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 60m -mod vendor -a ./test/integration/... --tags=integration

.PHONY: run-integration-test-k8s
run-integration-test-k8s:
	@echo "### Running integration tests"
	go clean -testcache
	go test -p 1 -failfast -v -timeout 60m -mod vendor -a ./test/integration/... --tags=integration_k8s

.PHONY: integration-test
integration-test: prereqs prepare-integration-test
	$(MAKE) run-integration-test || (ret=$$?; $(MAKE) cleanup-integration-test && exit $$ret)
	$(MAKE) itest-coverage-data
	$(MAKE) cleanup-integration-test

.PHONY: integration-test-k8s
integration-test-k8s: prereqs prepare-integration-test
	$(MAKE) run-integration-test-k8s || (ret=$$?; $(MAKE) cleanup-integration-test && exit $$ret)
	$(MAKE) itest-coverage-data
	$(MAKE) cleanup-integration-test

.PHONY: itest-coverage-data
itest-coverage-data:
	# merge coverage data from all the integration tests
	mkdir -p $(TEST_OUTPUT)/merge
	go tool covdata merge -i=$(TEST_OUTPUT) -o $(TEST_OUTPUT)/merge
	go tool covdata textfmt -i=$(TEST_OUTPUT)/merge -o $(TEST_OUTPUT)/itest-covdata.raw.txt
	# replace the unexpected /src/cmd/beyla/main.go file by the module path
	sed 's/^\/src\/cmd\//github.com\/grafana\/beyla\/cmd\//' $(TEST_OUTPUT)/itest-covdata.raw.txt > $(TEST_OUTPUT)/itest-covdata.all.txt
	# exclude generated files from coverage data
	grep -vE $(EXCLUDE_COVERAGE_FILES) $(TEST_OUTPUT)/itest-covdata.all.txt > $(TEST_OUTPUT)/itest-covdata.txt

bin/ginkgo:
	$(call go-install-tool,$(GINKGO),github.com/onsi/ginkgo/v2/ginkgo,latest)

.PHONY: oats-prereq
oats-prereq: bin/ginkgo
	mkdir -p $(TEST_OUTPUT)/run

.PHONY: oats-test-sql
oats-test-sql: oats-prereq
	mkdir -p test/oats/sql/$(TEST_OUTPUT)/run
	cd test/oats/sql && TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test-redis
oats-test-redis: oats-prereq
	mkdir -p test/oats/redis/$(TEST_OUTPUT)/run
	cd test/oats/redis && TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test-kafka
oats-test-kafka: oats-prereq
	mkdir -p test/oats/kafka/$(TEST_OUTPUT)/run
	cd test/oats/kafka && TESTCASE_TIMEOUT=120s TESTCASE_BASE_PATH=./yaml $(GINKGO) -v -r

.PHONY: oats-test
oats-test: oats-test-sql oats-test-redis oats-test-kafka
	$(MAKE) itest-coverage-data

.PHONY: oats-test-debug
oats-test-debug: oats-prereq
	cd test/oats/kafka && TESTCASE_BASE_PATH=./yaml TESTCASE_MANUAL_DEBUG=true TESTCASE_TIMEOUT=1h $(GINKGO) -v -r

.PHONY: drone
drone:
	@echo "### Regenerating and signing .drone/drone.yml"
	drone jsonnet --format --stream --source .drone/drone.jsonnet --target .drone/drone.yml
	drone lint .drone/drone.yml
	drone sign --save grafana/beyla .drone/drone.yml || echo "You must set DRONE_SERVER and DRONE_TOKEN. These values can be found on your [drone account](http://drone.grafana.net/account) page."

.PHONY: check-drone-drift
check-drone-drift:
	@echo "### checking that Drone.yml is up-to-date"
	./scripts/check-drone-drift.sh

.PHONY: update-licenses
update-licenses: prereqs
	@echo "### Updating third_party_licenses.csv"
	$(GO_LICENSES) report --include_tests ./... > third_party_licenses.csv

.PHONY: artifact
artifact: compile
	@echo "### Packing generated artifact"
	cp LICENSE ./bin
	cp NOTICE ./bin
	cp third_party_licenses.csv ./bin
	tar -C ./bin -cvzf bin/beyla.tar.gz beyla LICENSE NOTICE third_party_licenses.csv

.PHONY: clean-testoutput
clean-testoutput:
	@echo "### Cleaning ${TEST_OUTPUT} folder"
	rm -rf ${TEST_OUTPUT}/*

.PHONY: check-ebpf-integrity
check-ebpf-integrity: docker-generate
	git diff --name-status --exit-code || (echo "Run make docker-generate locally and commit the code changes" && false)
