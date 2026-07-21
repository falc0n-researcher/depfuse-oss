.PHONY: all build install test test-golden testdata fmt lint vet clean release docs docs-serve docs-clean-cache samples demo-gif docker

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
	cd docs && (bundle check >/dev/null 2>&1 || bundle install)
	cd docs && bundle exec jekyll build

docs-serve: docs-clean-cache
	cd docs && (bundle check >/dev/null 2>&1 || bundle install)
	cd docs && bundle exec jekyll serve --livereload --baseurl ""

docs-clean-cache:
	rm -rf docs/.jekyll-cache docs/_site

samples: build testdata
	DEPFUSE_OFFLINE=1 DEPFUSE_SKIP_AUTO_COLLECT=1 DEPFUSE_INTEL_DB=./testdata/intel.db \
		./bin/depfuse scan demo_package/ --format html --out-dir samples --quiet
	mv samples/report.html samples/scan.html
	DEPFUSE_OFFLINE=1 DEPFUSE_SKIP_AUTO_COLLECT=1 DEPFUSE_INTEL_DB=./testdata/intel.db \
		./bin/depfuse package next@15.1.0 --format html --out-dir samples --quiet
	mv samples/report-package.html samples/package.html
	DEPFUSE_OFFLINE=1 DEPFUSE_SKIP_AUTO_COLLECT=1 DEPFUSE_INTEL_DB=./testdata/intel.db \
		./bin/depfuse cve CVE-2025-29927 --format html --out-dir samples --quiet
	mv samples/report-cve.html samples/cve.html
	@rm -f samples/report.md samples/report-package.md samples/report-cve.md
	@echo "Samples updated in samples/"

demo-gif: build testdata
	@command -v asciinema >/dev/null || { echo "asciinema required: brew install asciinema"; exit 1; }
	@command -v agg >/dev/null || { echo "agg required: brew install agg"; exit 1; }
	asciinema rec --overwrite --command './scripts/record-package-demo.sh' \
		--title 'depfuse package express@4.17.1 --depth 2' --idle-time-limit 1 \
		--window-size 140x48 \
		docs/assets/casts/depfuse-package-express.cast
	agg --theme monokai --cols 140 --rows 48 --font-size 12 --speed 1 \
		--idle-time-limit 1 --fps-cap 20 --last-frame-duration 4 \
		docs/assets/casts/depfuse-package-express.cast \
		docs/assets/casts/depfuse-package-express.gif
	cp docs/assets/casts/depfuse-package-express.gif assets/depfuse-package-express.gif
	@echo "Demo GIF updated: docs/assets/casts/depfuse-package-express.gif and assets/depfuse-package-express.gif"

clean:
	rm -rf $(BIN_DIR)/ $(DIST_DIR)/ docs/_site docs/.jekyll-cache docs/.sass-cache

docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t depfuse:$(VERSION) \
		-t depfuse:latest .

release: clean
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-arm64 $(CMD)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-darwin-amd64 $(CMD)
	GOOS=linux  GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(DIST_DIR)/$(BINARY)-linux-amd64  $(CMD)
	@echo "Release binaries in $(DIST_DIR)/"

.DEFAULT_GOAL := build
