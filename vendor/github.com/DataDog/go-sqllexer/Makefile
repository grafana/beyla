.PHONY: build clean install test help

# Binary name
BINARY_NAME=sqllexer

# Build directory
BUILD_DIR=bin

# Default target
all: build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sqllexer

# Install the binary to GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(shell go env GOPATH)/bin/

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build the binary for current platform"
	@echo "  install     - Install binary to GOPATH/bin"
	@echo "  test        - Run tests"
	@echo "  bench       - Run benchmarks"
	@echo "  clean       - Clean build artifacts"
	@echo "  help        - Show this help message" 