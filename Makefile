.PHONY: all build install test test-golden testdata fmt lint vet clean release docs docs-serve

MODULE   := github.com/falc0n-researcher/depfuse-oss
BINARY   := depfuse
CMD      := ./cmd/depfuse
BIN_DIR  := bin
DIST_DIR := dist

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS  := -ldflags "-s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)"

GO       := go
GOFLAGS  ?=

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) $(CMD)

install:
	$(GO) install $(LDFLAGS) $(CMD)

test: testdata
	$(GO) test $(GOFLAGS) ./... -count=1 -race

test-golden: testdata
	$(GO) test $(GOFLAGS) ./internal/resolve/... ./internal/scan/... -run Golden -count=1 -race

testdata:
	@if [ ! -f testdata/intel.db ]; then \
		echo "Generating testdata/intel.db..."; \
		$(GO) run ./cmd/seed-testdata; \
	fi

fmt:
	@gofmt -w -s .

lint: fmt vet

vet:
	$(GO) vet ./...

docs:
	cd docs && bundle install && bundle exec jekyll build

docs-serve:
	cd docs && bundle install && bundle exec jekyll serve --livereload --baseurl ""

clean:
	rm -rf $(BIN_DIR)/ $(DIST_DIR)/ docs/_site docs/.jekyll-cache docs/.sass-cache

release: clean
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-arm64 $(CMD)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-amd64 $(CMD)
	GOOS=linux  GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-linux-amd64  $(CMD)
	@echo "Release binaries in $(DIST_DIR)/"

.DEFAULT_GOAL := build
