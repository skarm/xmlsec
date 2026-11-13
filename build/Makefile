GO ?= go
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_CONFIG ?= build/.golangci.yml
DOCKER ?= docker
INTEROP_DOCKER_TARGET ?= all
INTEROP_DOCKER_IMAGE ?= xmlsec-interop:$(if $(filter all,$(INTEROP_DOCKER_TARGET)),local,$(INTEROP_DOCKER_TARGET))
INTEROP_INPUT_CACHE ?= /tmp/xmlsec-interop-inputs
FUZZ_ARGS ?=
BENCH_ARGS ?=
INTEROP_ARGS ?=
SUITE_ARGS ?=

.PHONY: test check lint fmt modules docs race fuzz bench examples build suites interop interop-transforms interop-info interop-full interop-native interop-docker

test:
	$(GO) test ./...

lint:
	$(GOLANGCI_LINT) config verify --config "$(GOLANGCI_LINT_CONFIG)"
	$(GOLANGCI_LINT) run --config "$(GOLANGCI_LINT_CONFIG)" -v ./...

fmt:
	$(GOLANGCI_LINT) fmt --config "$(GOLANGCI_LINT_CONFIG)" ./...

check: modules docs
	$(GO) vet ./...
	$(GO) test ./...
	CGO_ENABLED=0 $(GO) build ./...

modules:
	$(GO) mod verify
	$(GO) mod tidy -diff

docs:
	$(GO) run ./tests/cmd/dev docs

race:
	$(GO) test -race ./...

fuzz:
	$(GO) run ./tests/cmd/dev fuzz $(FUZZ_ARGS)

bench:
	$(GO) test -p=1 ./... -run='^$$' -bench=. -benchmem $(BENCH_ARGS)

examples:
	$(GO) run ./tests/cmd/dev examples

build:
	$(GO) build -o bin/xmlsec ./cmd/xmlsec

# Optional, pinned external W3C test checkouts; never downloaded by the runner.
suites:
	$(GO) run ./tests/cmd/dev suites $(SUITE_ARGS)

# Optional independent engines; never part of ordinary Go checks.
interop:
	GO="$(GO)" bash build/interop.sh $(INTEROP_ARGS)

interop-transforms:
	XMLSEC_INTEROP_MODE=transforms XMLSEC_REQUIRE_P3_PROOFS=1 $(MAKE) interop

interop-info:
	$(GO) version
	xmlsec1 --version
	openssl version
	java -version
	pkg-config --modversion xmlsec1-openssl libxml-2.0

# The full local run includes race tests as well as both interop groups.
interop-full: interop-info
	$(GO) test -race -count=1 ./...
	$(MAKE) interop-services INTEROP_MODE=all

interop-native: INTEROP_MODE = native
interop-native: interop-info interop-services

.PHONY: interop-services
interop-services:
	XMLSEC_P7_EXPORT_FIXTURES=/tmp/xmlsec-interop-history $(GO) test -count=1 ./xades -run '^TestHistoricalExpiredTSAArchiveEvidence$$'
	XMLSEC_INTEROP_MODE=$(INTEROP_MODE) XMLSEC_DSS_FIXTURE_DIR=/tmp/xmlsec-interop-history XMLSEC_DSS_CA_PEM=root.pem sh build/dss.sh --inside-all

interop-docker:
	sh build/prepare-interop.sh "$(INTEROP_INPUT_CACHE)" "$(INTEROP_DOCKER_TARGET)"
	$(DOCKER) build --target "$(INTEROP_DOCKER_TARGET)" --build-context "interop-downloads=$(INTEROP_INPUT_CACHE)" --file build/interop.Dockerfile --tag "$(INTEROP_DOCKER_IMAGE)" .
	$(DOCKER) run --rm --network=none --env XMLSEC_INTEROP_TRANSFORM_PARTS --env XMLSEC_INTEROP_TRANSFORM_PART "$(INTEROP_DOCKER_IMAGE)"
