# Copyright 2026 Kentrow
# SPDX-License-Identifier: Apache-2.0

# Build information injected into the binary and the image. Each value can be overridden on
# the command line, for example: make docker VERSION=0.1.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE   ?= keymaker

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

GOVULNCHECK_VERSION ?= v1.8.0

# How long make fuzz explores each target. go test already replays their seeds, and the inputs
# a run has found to fail, on every run; this is for looking further.
FUZZTIME ?= 30s
FUZZ_TARGETS := \
	./internal/config:FuzzParse \
	./internal/catalog:FuzzParseIndex \
	./internal/catalog:FuzzParseSchema \
	./internal/httpapi:FuzzReadAddresses \
	./internal/ovh:FuzzParsePrefix \
	./internal/ovh:FuzzCredentialDecoding \
	./internal/ovh:FuzzRetryAfter

# govulncheck has to run on the toolchain the module declares: a binary built with an older Go
# cannot load packages that require a newer one.
TOOLCHAIN := $(shell awk '/^toolchain/ {print $$2}' go.mod)

.DEFAULT_GOAL := help

.PHONY: help check build test lint markdown vuln fuzz snapshot demo docker

help: ## List the available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

check: lint markdown test vuln ## Run every check CI runs, in its order: what a pull request is held to

build: ## Build the keymaker binary into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/keymaker ./cmd/keymaker

test: ## Run the test suite with the race detector and coverage
	go test -race -coverprofile=coverage.out ./...

lint: ## Check formatting, module tidiness and run golangci-lint
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go mod tidy -diff
	golangci-lint run ./...

markdown: ## Check the Markdown files against .markdownlint-cli2.jsonc, as CI does (needs npx)
	@command -v npx >/dev/null || { echo "npx not found: install Node.js to check the Markdown as CI does"; exit 1; }
	npx --yes markdownlint-cli2 $$(git ls-files '*.md')

vuln: ## Check dependencies and the standard library against the Go vulnerability database
	GOTOOLCHAIN=$(TOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

fuzz: ## Explore every fuzz target for FUZZTIME each (30s by default)
	@set -e; for target in $(FUZZ_TARGETS); do \
		echo "$${target#*:}"; \
		go test "$${target%%:*}" -run '^$$' -fuzz "^$${target#*:}$$" -fuzztime $(FUZZTIME); \
	done

snapshot: ## Regenerate the embedded API catalogue from the live OVHcloud API
	go run ./tools/snapshotgen

demo: ## Run the interface on invented data, without an OVHcloud account
	go run ./tools/demo

docker: ## Build the container image for the local platform
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE):$(VERSION) .
