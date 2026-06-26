# marmot Makefile
#
# Targets:
#   build         — Build marmot binary for the current platform
#   build-arm     — Cross-compile for ARM (Raspberry Pi 2/3/4)
#   build-arm64   — Cross-compile for ARM64
#   clean         — Remove build artifacts
#   test          — Run unit tests
#   lint          — Run linters (if available)
#   run           — Run marmot locally with default config
#   fmt           — Format Go source code
#   dev           — Run with hot-reload (requires reflex/air)

GO          := /usr/local/go/bin/go
GOOS        := linux
CGO_ENABLED ?= 0
LDFLAGS     := -ldflags="-s -w"

# Default target
.PHONY: all
all: build

# --- Build ---

.PHONY: build
build:
	@echo "Building marmot (linux/amd64)..."
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=amd64 $(GO) build -tags with_utls $(LDFLAGS) -o build/marmot ./cmd/marmot/
	@echo "Built: build/marmot"

.PHONY: build-arm
build-arm:
	@echo "Cross-compiling marmot for linux/arm (v7)..."
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=arm GOARM=7 $(GO) build -tags with_utls $(LDFLAGS) -o build/marmot-arm ./cmd/marmot/
	@echo "Built: build/marmot-arm"

.PHONY: build-arm64
build-arm64:
	@echo "Cross-compiling marmot for linux/arm64..."
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=arm64 $(GO) build $(LDFLAGS) -o build/marmot-arm64 ./cmd/marmot/
	@echo "Built: build/marmot-arm64"

.PHONY: build-all
build-all: build build-arm build-arm64

# --- Clean ---

.PHONY: clean
clean:
	rm -rf build/

# --- Test ---

.PHONY: test
test:
	@echo "Running tests..."
	$(GO) test -v -race -count=1 ./...

.PHONY: test-short
test-short:
	@echo "Running short tests..."
	$(GO) test -short -count=1 ./...

# --- Lint / Format ---

.PHONY: lint
lint:
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

.PHONY: fmt
fmt:
	$(GO) fmt ./...

# --- Run ---

.PHONY: run
run: build
	@echo "Running marmot (skeleton mode)..."
	./build/marmot -config configs/marmot.yaml

.PHONY: run-arm
run-arm: build-arm
	@echo "Running arm binary (via qemu or ssh)..."
	@echo "To run on Raspberry Pi:"
	@echo "  scp build/marmot-arm root@172.28.0.3:/tmp/marmot"
	@echo "  ssh root@172.28.0.3 /tmp/marmot --version"

# --- Tidy ---

.PHONY: tidy
tidy:
	$(GO) mod tidy
	$(GO) mod verify

# --- Help ---

.PHONY: help
help:
	@echo "marmot Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build for linux/amd64"
	@echo "  build-arm      Cross-compile for linux/arm"
	@echo "  build-arm64    Cross-compile for linux/arm64"
	@echo "  build-all      All three architectures"
	@echo "  clean          Remove build artifacts"
	@echo "  test           Run unit tests"
	@echo "  lint           Run linters"
	@echo "  fmt            Format Go code"
	@echo "  run            Build and run locally"
	@echo "  tidy           Run go mod tidy + verify"
