# dmarc-monitor — watch a mailbox for DMARC aggregate reports and alert a human
# when they say something worth acting on.
#
# Targets mirror the sibling project's workflow (build / vet / fmt / lint /
# test) so the same habits apply here.
#
# Offline: everything here runs from the module cache after one `make deps`,
# with one exception -- `vuln-check` queries the Go vulnerability database over
# the network on every run, and `make test` includes it. On a machine with no
# network, run `make test-unit lint` instead.

GO          ?= go
BINARY      ?= dmarc-monitor
CMD         ?= ./cmd/dmarc-monitor
CREDENTIALS ?= $(HOME)/.local/share/dmarc-monitor/credentials.env

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n", $$1, $$2}'

.PHONY: deps
deps: ## Download module dependencies into the module cache
	$(GO) mod download

.PHONY: build
build: ## Build the binary
	$(GO) build -o $(BINARY) $(CMD)

.PHONY: init-credentials
init-credentials: ## Write a commented credentials template to ~/.local/share/dmarc-monitor
	$(GO) run $(CMD) -init-credentials

.PHONY: run
run: ## Run one polling cycle, printing the alert instead of sending it
	$(GO) run $(CMD) -once -dry-run

.PHONY: check
check: ## Verify credentials parse and both endpoints are reachable (connects!)
	$(GO) run $(CMD) -check

.PHONY: vet
vet: ## go vet the whole module
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format all Go sources in place
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is not gofmt-clean
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: lint
lint: vet fmt-check ## vet + gofmt check

.PHONY: vuln-check
vuln-check: ## Check dependencies against the Go vulnerability database (needs network)
	$(GO) tool govulncheck ./...

.PHONY: test-unit
test-unit: ## Run unit tests
	$(GO) test ./...

.PHONY: test-integration
test-integration: ## Run integration tests (needs a real mailbox; see README)
	$(GO) test -tags=integration ./...

.PHONY: test
test: test-unit lint vuln-check ## Full check: unit tests + lint + vulnerability scan

.PHONY: cover
cover: ## Unit tests with a coverage summary
	$(GO) test -cover ./...

.PHONY: tidy
tidy: ## Tidy go.mod
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BINARY)
