GO      ?= go
GOOS    ?= linux
GOARCH  ?= $(shell $(GO) env GOARCH)
BIN     ?= tpmlsm
GO_LDFLAGS ?= -s -w

.DEFAULT_GOAL := build

.PHONY: help build generate test vet check clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build tpmlsm for Linux (override GOOS/GOARCH to cross-compile)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -ldflags "$(GO_LDFLAGS)" -o $(BIN) ./cmd/tpmlsm

generate: bpf/vmlinux.h ## Regenerate the BPF objects (Linux only: clang, libbpf, bpftool)
	$(GO) generate ./cmd/tpmlsm

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

test: ## Run the unit tests
	$(GO) test ./...

vet: ## Run go vet against the Linux build
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) vet ./...

check: vet test ## Run vet and tests, and fail on unformatted Go files
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

clean: ## Remove the binary and the generated vmlinux.h
	rm -f $(BIN) bpf/vmlinux.h
