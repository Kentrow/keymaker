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

# govulncheck has to run on the toolchain the module declares: a binary built with an older Go
# cannot load packages that require a newer one.
TOOLCHAIN := $(shell awk '/^toolchain/ {print $$2}' go.mod)

.DEFAULT_GOAL := help

.PHONY: help build test lint vuln snapshot docker

help: ## List the available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the keymaker binary into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/keymaker ./cmd/keymaker

test: ## Run the test suite with the race detector and coverage
	go test -race -coverprofile=coverage.out ./...

lint: ## Check formatting, module tidiness and run golangci-lint
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go mod tidy -diff
	golangci-lint run ./...

vuln: ## Check dependencies and the standard library against the Go vulnerability database
	GOTOOLCHAIN=$(TOOLCHAIN) go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

snapshot: ## Regenerate the embedded API catalogue from the live OVHcloud API
	go run ./tools/snapshotgen

docker: ## Build the container image for the local platform
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(IMAGE):$(VERSION) .
