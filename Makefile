# dmarc-monitor — watch a mailbox for DMARC aggregate reports and alert a human
# when they say something worth acting on.
#
# Targets mirror the sibling projects' workflow (build / vet / fmt / lint /
# test, and deploy-* / prod-* for a person at a terminal) so the same habits
# apply here.
#
# Offline: everything here runs from the module cache after one `make deps`,
# with one exception -- `vuln-check` queries the Go vulnerability database over
# the network on every run, and `make test` includes it. On a machine with no
# network, run `make test-unit lint` instead.

GO          ?= go
BINARY      ?= dmarc-monitor
CMD         ?= ./cmd/dmarc-monitor

# VERSION and COMMIT are stamped into the binary. The deploy notice names the
# first and links the second, and the binary records VERSION in state.json to
# notice the first run of a new build. git describe names the last tag and how
# far past it the tree is, so every commit on main deploys under a distinct
# version without anybody cutting a tag.
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse HEAD 2>/dev/null)
LDFLAGS     ?= -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.DEFAULT_GOAL := help

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  %-20s %s\n", $$1, $$2}'

# ---------------------------------------------------------------- build

.PHONY: deps
deps: ## Download module dependencies into the module cache
	$(GO) mod download

.PHONY: build
build: ## Build the binary for this machine
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

.PHONY: version
version: ## Show the version this tree would build as
	@echo $(VERSION)

# konsoleH has no Go toolchain and receives one file, so a build that quietly
# links this machine's libc is a deploy that dies on the host. CGO stays off,
# and the assertion below is what makes that a fact rather than an intention.
.PHONY: release-build
release-build: ## Build the static linux/amd64 binary the server runs
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(BINARY)-linux-amd64 $(CMD)
	@file $(BINARY)-linux-amd64 | grep -q 'statically linked' \
		|| { echo "$(BINARY)-linux-amd64 is not statically linked" >&2; exit 1; }
	@echo "$(BINARY)-linux-amd64 is static ($(VERSION))"

# ---------------------------------------------------------------- run locally
#
# These read the credentials in ~/.local/share/dmarc-monitor/, which is the
# disposable test mailbox (AGENTS.md). make local-credentials writes that file
# from the DEV_* group in secrets.env.

.PHONY: init-credentials
init-credentials: ## Write a commented credentials template to ~/.local/share/dmarc-monitor
	$(GO) run $(CMD) -init-credentials

.PHONY: run
run: ## Run one polling cycle, printing the alert instead of sending it
	$(GO) run $(CMD) -once -dry-run

.PHONY: check
check: ## Verify credentials parse and both endpoints are reachable (connects!)
	$(GO) run $(CMD) -check

# ---------------------------------------------------------------- the checks

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
test-unit: ## Run unit tests, with the race detector
	$(GO) test -race ./...

.PHONY: test-integration
test-integration: ## Run integration tests (needs a real mailbox; see README)
	$(GO) test -tags=integration ./...

.PHONY: shell-test
shell-test: ## Run the shell tests (secrets rendering, the crontab rewrite)
	@for t in scripts/*-test.sh; do \
		[ -f "$$t" ] || continue; \
		echo "--- $$t"; \
		bash "$$t" || exit 1; \
	done

.PHONY: shellcheck
shellcheck: ## Lint the shell scripts (CI has shellcheck; locally, install it first)
	shellcheck -x -P SCRIPTDIR scripts/secrets scripts/env.sh scripts/*-test.sh deploy/deploy.sh

.PHONY: test
test: test-unit lint shell-test vuln-check ## Full check: unit + shell tests + lint + vulnerability scan

.PHONY: cover
cover: ## Unit tests with a coverage summary
	$(GO) test -cover ./...

.PHONY: tidy
tidy: ## Tidy go.mod
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BINARY) $(BINARY)-linux-amd64

# ---------------------------------------------------------------- the server
#
# Everything below reads secrets.env, which is not in the repository. It lives
# in Bitwarden; see secrets.env.example for what goes in it and where each group
# is sent.
#
# These are for a person at a terminal. .claude/settings.json denies make
# deploy*, make prod-* and make local-credentials to agents: every one of them
# reads the production secrets or acts as the production mailbox.

.PHONY: deploy-status
deploy-status: ## Ready to deploy? secrets.env, GitHub, the server, the pipeline
	@scripts/secrets status

.PHONY: deploy-keygen
deploy-keygen: ## Mint this project's deploy ssh key, and print how to install it
	@scripts/secrets ssh-keygen

.PHONY: deploy-known-hosts
deploy-known-hosts: ## Pin the server's host key (paste the line into secrets.env)
	@scripts/secrets known-hosts

.PHONY: deploy-send-secrets
deploy-send-secrets: ## Deploy key and paths to GitHub; credentials.env to the server
	@scripts/secrets push
	@scripts/secrets install

.PHONY: deploy
deploy: ## Deploy from this machine. The ordinary path is a push to main
	@deploy/deploy.sh deploy

.PHONY: local-credentials
local-credentials: ## Write ~/.local/share/dmarc-monitor/credentials.env from the DEV_* group
	@scripts/secrets local

.PHONY: prod-status
prod-status: ## What is installed and scheduled on the server, and the last runs
	@deploy/deploy.sh status

.PHONY: prod-logs
prod-logs: ## The tail of the server's cron.log (make prod-logs N=200)
	@deploy/deploy.sh logs $(or $(N),80)

.PHONY: prod-check
prod-check: ## Run -check on the server: mailbox and relay reachable. Sends nothing
	@deploy/deploy.sh check

.PHONY: prod-dry-run
prod-dry-run: ## Run one cycle on the server and print the alert. Sends and changes nothing
	@deploy/deploy.sh dry-run

.PHONY: prod-test-alert
prod-test-alert: ## Send ONE REAL test message from the server, and print its Message-ID
	@deploy/deploy.sh test-alert

.PHONY: prod-rollback
prod-rollback: ## Put the previous binary back (run again to roll forward)
	@deploy/deploy.sh rollback
