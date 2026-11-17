.PHONY: bench check tests clean

tests: check

check:
	@go test ./... -benchmem -race

clean:
	@rm *.test */*.test

bench:
	@(cd bench; go test -bench=. -run XXX)

GOLANGCI_LINT_VERSION = "v1.60.1"
lint:
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run
